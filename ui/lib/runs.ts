/**
 * Runs started from the UI: `node bin/cli.ts ci --project <name>` or `node bin/cli.ts run --plan ... --config ...`
 * as a child process (its own process group, so cancelling stops Playwright, its worker and the target).
 *
 * Before the run, the same command with `--list --reporter=json` gives the modules it will run, in order. While it
 * runs, progress comes from two places: the console reporter's line for each finished module ("✓ oidcc-server  1.2s"), which also tells which module runs next, and the module-report.json each finished module
 * leaves in the run's output directory (polled), which has the module's result and analysis.
 *
 * Every run gets an output directory of its own (<results dir>/<project or plan-hash>/<run id>) because Playwright
 * empties its output directory when a run starts; the last KEEP_RUNS of each project are kept. One run at a time per report directory: the active run is kept in memory
 * and in <report dir>/.ui-run.lock (with the server's pid) so a second UI on the same directory refuses too.
 * Finished runs are kept in <report dir>/ui-runs.json.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { findProject, plans } from "./catalog.ts";
import { globMatch, moduleName, outcomeOf, variantString } from "./format.ts";
import { cliPath, reportDir, resultsDir, runCwd, suiteRoot } from "./paths.ts";
import type { ModuleReport, Outcome, RunEvent, RunInfo, RunModule, RunRequest } from "./types.ts";

const MAX_OUTPUT_LINES = 5000;
const SNAPSHOT_OUTPUT_LINES = 1500;
const MAX_HISTORY = 50;
const KEEP_RUNS = 5;

interface Run {
	info: RunInfo;
	output: string[];
	emitter: EventEmitter;
	child: ChildProcess | null;
	cancelled: boolean;
	poll: NodeJS.Timeout | null;
	seenReports: Set<string>;
}

interface Registry {
	runs: Map<string, Run>;
	active: string | null;
}

// survives Next.js dev reloads of this module
const registry: Registry = ((globalThis as { __conformanceUiRuns?: Registry }).__conformanceUiRuns ??= {
	runs: new Map(),
	active: null,
});

export class RunError extends Error {
	override name = "RunError";
	status: number;
	runId?: string;
	constructor(message: string, status = 400, runId?: string) {
		super(message);
		this.status = status;
		this.runId = runId;
	}
}

const lockFile = join(reportDir, ".ui-run.lock");
const historyFile = join(reportDir, "ui-runs.json");

function alive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

async function acquireLock(runId: string): Promise<void> {
	await mkdir(reportDir, { recursive: true });
	try {
		const lock = JSON.parse(await readFile(lockFile, "utf8")) as { pid: number; runId: string };
		if (lock.pid !== process.pid && alive(lock.pid)) {
			throw new RunError(`another UI (pid ${lock.pid}) is running ${lock.runId} on ${reportDir}`, 409);
		}
	} catch (e) {
		if (e instanceof RunError) {
			throw e;
		}
		// no lock, or a stale one
	}
	await writeFile(lockFile, JSON.stringify({ pid: process.pid, runId }));
}

async function releaseLock(): Promise<void> {
	await rm(lockFile, { force: true });
}

/** The CLI arguments and environment of a request (bin/cli.ts `ci` / `run`); throws RunError when invalid */
function command(req: RunRequest): {
	args: string[];
	env: Record<string, string>;
	plan: string;
	variant: string;
	label: string;
	slug: string;
} {
	const env: Record<string, string> = {
		CONFORMANCE_REPORT_DIR: reportDir,
		FORCE_COLOR: "0",
		NO_COLOR: "1",
		CONFORMANCE_VIDEO: req.options?.video ? "on" : "off",
	};
	if (req.options?.verbose) {
		env["CONFORMANCE_VERBOSE"] = "1";
	}
	const module = req.module?.trim();
	if (req.kind === "project") {
		const project = findProject(req.project);
		if (!project) {
			throw new RunError(`unknown project '${req.project}'`);
		}
		if (module) {
			env["CONFORMANCE_MODULE"] = module;
		}
		return {
			args: [cliPath, "ci", "--project", project.name],
			env,
			plan: project.plan,
			variant: project.variant,
			label: project.name + (module ? ` (${module})` : ""),
			slug: project.name,
		};
	}
	const plan = plans[req.plan];
	if (!plan) {
		throw new RunError(`unknown plan '${req.plan}'`);
	}
	const config = resolve(runCwd, req.config);
	if (!req.config || !existsSync(config)) {
		throw new RunError(`config not found: ${req.config}`);
	}
	const args = [cliPath, "run", "--plan", req.plan, "--config", config, "--report-dir", reportDir];
	for (const [k, v] of Object.entries(req.variant ?? {})) {
		if (!v) {
			continue;
		}
		if (!plan.variants[k]?.includes(v)) {
			throw new RunError(`variant ${k}=${v} is not one of ${req.plan}'s`);
		}
		args.push("--variant", `${k}=${v}`);
	}
	if (module) {
		args.push("--module", module);
	}
	if (req.tls) {
		args.push("--tls");
	}
	const variant = variantString(Object.fromEntries(Object.entries(req.variant ?? {}).filter(([, v]) => v)));
	const hash = createHash("sha256").update(`${req.plan}\n${config}\n${variant}`).digest("hex").slice(0, 8);
	return {
		args,
		env,
		plan: req.plan,
		variant,
		label: req.plan.replace(/-certification-test-plan$|-test-plan$/, "") + (module ? ` (${module})` : ""),
		slug: `plan-${hash}`,
	};
}

/** The tests the command will run, in order (Playwright `--list --reporter=json`) */
async function listTests(args: string[], env: Record<string, string>): Promise<string[]> {
	const out = await new Promise<string>((done, fail) => {
		const child = spawn(process.execPath, [...args, "--", "--list", "--reporter=json"], {
			cwd: runCwd,
			env: { ...process.env, ...env },
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
		child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
		child.on("error", fail);
		child.on("close", (code) =>
			code === 0
				? done(stdout)
				: fail(new RunError(`listing the tests failed: ${(stderr || stdout).trim().slice(-2000)}`, 500)),
		);
	});
	interface Suite {
		specs?: { title: string }[];
		suites?: Suite[];
	}
	const json = JSON.parse(out.slice(out.indexOf("{"))) as { suites?: Suite[]; errors?: { message?: string }[] };
	if (json.errors?.length) {
		throw new RunError(`listing the tests failed: ${json.errors.map((e) => e.message).join("\n")}`, 500);
	}
	const titles: string[] = [];
	const walk = (s: Suite) => {
		s.specs?.forEach((spec) => titles.push(spec.title));
		s.suites?.forEach(walk);
	};
	json.suites?.forEach(walk);
	return titles;
}

function emit(run: Run, event: RunEvent): void {
	run.emitter.emit("event", event);
}

function appendOutput(run: Run, lines: string[]): void {
	run.output.push(...lines);
	if (run.output.length > MAX_OUTPUT_LINES) {
		run.output.splice(0, run.output.length - MAX_OUTPUT_LINES);
	}
	emit(run, { type: "output", lines });
	for (const line of lines) {
		progressFromLine(run, line);
	}
}

function setModule(run: Run, index: number, update: Partial<RunModule>): void {
	const module = { ...run.info.modules[index], ...update };
	run.info.modules[index] = module;
	emit(run, { type: "module", index, module });
}

/** Marks the first pending module running (one worker: modules run in list order) */
function markNextRunning(run: Run): void {
	if (run.info.status !== "running" || run.info.modules.some((m) => m.state === "running")) {
		return;
	}
	const next = run.info.modules.findIndex((m) => m.state === "pending");
	if (next >= 0) {
		setModule(run, next, { state: "running", outcome: "running" });
	}
}

// the suite's console reporter (src/suite/report.ts): a header "<title>: N modules", then one line per finished
// module: "<glyph> <module>  <duration>  <note>" with ✓ passed, ? review, - skipped, ~ expected failure, ✗ failed
const MODULE_END = /^\s*(✓|\?|-|~|✗)\s+(\S+)\s+(\d+m\d+s|\d+(?:\.\d+)?s)(?:\s{2,}(.*))?\s*$/;

function parseDuration(text: string): number {
	const m = /^(?:(\d+)m)?(\d+(?:\.\d+)?)s$/.exec(text);
	return m ? Number(m[1] ?? 0) * 60_000 + Number(m[2]) * 1000 : 0;
}

function progressFromLine(run: Run, line: string): void {
	if (/^\S.*: \d+ modules?$/.test(line.trim())) {
		markNextRunning(run);
		return;
	}
	const m = MODULE_END.exec(line);
	if (!m) {
		return;
	}
	const index = run.info.modules.findIndex((x) => x.name === m[2] && x.state !== "done");
	if (index < 0) {
		return;
	}
	const current = run.info.modules[index];
	const mark = m[1];
	const provisional: Outcome =
		mark === "-"
			? "skipped"
			: mark === "✗"
				? "failed"
				: mark === "?"
					? "review"
					: mark === "~"
						? "expected-failure"
						: "passed";
	setModule(run, index, {
		state: "done",
		// the module report (if already read) knows better than the reporter's mark
		outcome: current.testId ? current.outcome : provisional,
		durationMs: current.durationMs ?? parseDuration(m[3]),
	});
	markNextRunning(run);
}

/** Reads the module reports that appeared in the run's output directory */
async function scanReports(run: Run): Promise<void> {
	const dir = join(resultsDir, run.info.outputDir);
	let entries: string[];
	try {
		entries = await readdir(dir);
	} catch {
		return;
	}
	for (const name of entries) {
		if (run.seenReports.has(name)) {
			continue;
		}
		const file = join(dir, name, "module-report.json");
		let report: ModuleReport;
		try {
			report = JSON.parse(await readFile(file, "utf8")) as ModuleReport;
		} catch {
			continue; // not written (completely) yet
		}
		run.seenReports.add(name);
		const title = report.title.split(" › ").at(-1) ?? report.title;
		const index = run.info.modules.findIndex((x) => x.title === title);
		if (index >= 0) {
			setModule(run, index, {
				outcome: outcomeOf(report),
				testId: report.testId,
				durationMs: report.durationMs,
			});
		}
	}
}

async function readHistory(): Promise<RunInfo[]> {
	try {
		return JSON.parse(await readFile(historyFile, "utf8")) as RunInfo[];
	} catch {
		return [];
	}
}

async function saveHistory(info: RunInfo): Promise<void> {
	const history = (await readHistory()).filter((r) => r.id !== info.id);
	history.unshift(info);
	await mkdir(reportDir, { recursive: true });
	await writeFile(historyFile, JSON.stringify(history.slice(0, MAX_HISTORY), null, 2));
}

/** Removes all but the newest KEEP_RUNS run directories of a project (run ids start with their time) */
async function pruneRuns(slug: string): Promise<void> {
	const dir = join(resultsDir, slug);
	const runs = (await readdir(dir, { withFileTypes: true }))
		.filter((e) => e.isDirectory() && /^\d{14}-[0-9a-f]+$/.test(e.name))
		.map((e) => e.name)
		.sort();
	for (const old of runs.slice(0, Math.max(0, runs.length - KEEP_RUNS))) {
		await rm(join(dir, old), { recursive: true, force: true });
	}
}

async function finish(run: Run, status: RunInfo["status"], exitCode: number | null, error?: string): Promise<void> {
	if (run.poll) {
		clearInterval(run.poll);
		run.poll = null;
	}
	await scanReports(run).catch(() => undefined);
	const modules = run.info.modules.map((m): RunModule => {
		if (m.state === "done") {
			return m;
		}
		return {
			...m,
			state: "done",
			outcome: m.state === "running" ? (run.cancelled ? "cancelled" : "interrupted") : "not-run",
		};
	});
	run.info = { ...run.info, status, exitCode, error, endedAt: Date.now(), modules };
	emit(run, { type: "modules", modules });
	emit(run, { type: "status", run: run.info });
	if (registry.active === run.info.id) {
		registry.active = null;
		await releaseLock().catch(() => undefined);
	}
	await saveHistory(run.info).catch(() => undefined);
	await pruneRuns(dirname(run.info.outputDir)).catch(() => undefined);
	run.child = null;
}

// ANSI colour codes some tools print despite NO_COLOR
// oxlint-disable-next-line no-control-regex
const ANSI = /\u001b\[[0-9;]*[A-Za-z]/g;

function splitLines(run: Run, stream: NodeJS.ReadableStream): void {
	let buffer = "";
	stream.on("data", (d: Buffer) => {
		buffer += d.toString("utf8");
		const parts = buffer.split(/\r?\n/);
		buffer = parts.pop() ?? "";
		if (parts.length > 0) {
			appendOutput(
				run,
				parts.map((l) => l.replace(ANSI, "")),
			);
		}
	});
	stream.on("end", () => {
		if (buffer) {
			appendOutput(run, [buffer]);
			buffer = "";
		}
	});
}

/** Starts a run; rejects with RunError 409 when one is already running on this report directory */
export async function startRun(req: RunRequest): Promise<RunInfo> {
	if (registry.active) {
		throw new RunError(`a run is already in progress (${registry.active})`, 409, registry.active);
	}
	const cmd = command(req);
	const id = `${new Date().toISOString().replace(/\D/g, "").slice(0, 14)}-${randomBytes(3).toString("hex")}`;
	registry.active = id;
	try {
		await acquireLock(id);
	} catch (e) {
		registry.active = null;
		throw e;
	}
	const outputDir = join(cmd.slug, id);
	cmd.env["PLAYWRIGHT_TEST_OUTPUT_DIR"] = join(resultsDir, outputDir);
	const run: Run = {
		info: {
			id,
			label: cmd.label,
			request: req,
			plan: cmd.plan,
			variant: cmd.variant,
			command: ["node", relative(runCwd, cmd.args[0]) || cmd.args[0], ...cmd.args.slice(1)]
				.map((a) => (a.startsWith(suiteRoot + "/") ? relative(suiteRoot, a) : a))
				.join(" "),
			outputDir,
			status: "starting",
			startedAt: Date.now(),
			modules: [],
		},
		output: [],
		emitter: new EventEmitter().setMaxListeners(100),
		child: null,
		cancelled: false,
		poll: null,
		seenReports: new Set(),
	};
	registry.runs.set(id, run);
	void execute(run, cmd);
	return run.info;
}

async function execute(run: Run, cmd: ReturnType<typeof command>): Promise<void> {
	try {
		appendOutput(run, [`$ ${run.info.command}`]);
		const titles = await listTests(cmd.args, cmd.env);
		if (run.cancelled) {
			await finish(run, "cancelled", null);
			return;
		}
		const glob = run.info.request.module?.trim();
		run.info.modules = titles
			.filter((t) => !glob || globMatch(glob, moduleName(t)))
			.map((title) => ({ title, name: moduleName(title), state: "pending", outcome: "pending" }));
		if (run.info.modules.length === 0) {
			await finish(run, "error", null, "no test module matches");
			return;
		}
		run.info.status = "running";
		emit(run, { type: "status", run: run.info });
		emit(run, { type: "modules", modules: run.info.modules });

		const child = spawn(process.execPath, cmd.args, {
			cwd: runCwd,
			env: { ...process.env, ...cmd.env },
			stdio: ["ignore", "pipe", "pipe"],
			detached: true,
		});
		run.child = child;
		splitLines(run, child.stdout);
		splitLines(run, child.stderr);
		run.poll = setInterval(() => void scanReports(run).catch(() => undefined), 1000);
		child.on("error", (e) => void finish(run, "error", null, e.message));
		child.on("close", (code) => {
			const status = run.cancelled ? "cancelled" : code === 0 ? "passed" : "failed";
			void finish(run, status, code);
		});
	} catch (e) {
		const message = e instanceof Error ? e.message : String(e);
		appendOutput(run, message.split("\n"));
		await finish(run, run.cancelled ? "cancelled" : "error", null, message);
	}
}

/** Stops the run's process group (SIGTERM, SIGKILL after 5 s) */
export function cancelRun(id: string): RunInfo {
	const run = registry.runs.get(id);
	if (!run) {
		throw new RunError(`unknown run '${id}'`, 404);
	}
	if (run.info.endedAt) {
		return run.info;
	}
	run.cancelled = true;
	appendOutput(run, ["", "Cancelling the run..."]);
	const pid = run.child?.pid;
	if (pid) {
		const kill = (signal: NodeJS.Signals) => {
			try {
				process.kill(-pid, signal);
			} catch {
				// already gone
			}
		};
		kill("SIGTERM");
		setTimeout(() => {
			if (run.child) {
				kill("SIGKILL");
			}
		}, 5000).unref();
	}
	return run.info;
}

export function activeRunId(): string | null {
	return registry.active;
}

export function getRun(id: string): { info: RunInfo; output: string[] } | null {
	const run = registry.runs.get(id);
	return run ? { info: run.info, output: run.output.slice(-SNAPSHOT_OUTPUT_LINES) } : null;
}

/** The run, from memory or (after a restart) from the history; output only while it is in memory */
export async function findRun(id: string): Promise<{ info: RunInfo; output: string[] } | null> {
	const live = getRun(id);
	if (live) {
		return live;
	}
	const info = (await readHistory()).find((r) => r.id === id);
	return info ? { info, output: [] } : null;
}

/** Runs of this server and earlier ones (ui-runs.json), newest first */
export async function listRuns(): Promise<RunInfo[]> {
	const history = await readHistory();
	const live = [...registry.runs.values()].map((r) => r.info);
	const ids = new Set(live.map((r) => r.id));
	return [...live, ...history.filter((r) => !ids.has(r.id))].sort((a, b) => b.startedAt - a.startedAt);
}

/** Subscribes to a run's events; the first event is a snapshot. Returns the unsubscribe function */
export function subscribe(id: string, listener: (e: RunEvent) => void): (() => void) | null {
	const run = registry.runs.get(id);
	if (!run) {
		return null;
	}
	listener({ type: "snapshot", run: run.info, output: run.output.slice(-SNAPSHOT_OUTPUT_LINES) });
	run.emitter.on("event", listener);
	return () => run.emitter.off("event", listener);
}

/**
 * Reads what a conformance run leaves behind (src/suite/report.ts, tests/fixtures.ts):
 *
 *   <report dir>/results.json                        every module report, merged across runs (by test title)
 *   <results dir>/<test dir>/module-report.json, log.json, log.html, *.png, video.webm, trace.zip   (CLI runs)
 *   <results dir>/<project>/<run id>/<test dir>/...                                                 (UI runs)
 *
 * Playwright empties its output directory at the start of each run, so the UI gives each of its runs a directory of
 * its own (runs.ts) and this scans up to two levels of nesting. The newest report of a module wins. Rows of
 * results.json whose directory is gone are still shown, without a log.
 */
import { connection } from "next/server";
import { readdir, readFile, stat } from "node:fs/promises";
import { basename, join, relative } from "node:path";
import { planKind, plans, projects } from "./catalog.ts";
import { isOk, outcomeOf, parseVariant } from "./format.ts";
import { hosted } from "./mode.ts";
import { inside, reportDir, resultsDir, sampleDir } from "./paths.ts";
import type { ConformanceProject, LogEntry, ModuleRecord, ModuleReport, ModuleStatus, ProjectStatus } from "./types.ts";

async function exists(path: string): Promise<boolean> {
	return stat(path).then(
		() => true,
		() => false,
	);
}

async function readJson<T>(path: string): Promise<T | null> {
	try {
		return JSON.parse(await readFile(path, "utf8")) as T;
	} catch {
		return null;
	}
}

async function subdirectories(dir: string): Promise<string[]> {
	try {
		const entries = await readdir(dir, { withFileTypes: true });
		return entries
			.filter((e) => e.isDirectory() && e.name !== "attachments" && !e.name.startsWith("."))
			.map((e) => join(dir, e.name));
	} catch {
		return [];
	}
}

/**
 * When each bundled module finished (sample-data/manifest.json, written by scripts/sample-data.ts): file times do
 * not survive a git checkout or a deployment
 */
async function bundledTimes(): Promise<Record<string, number>> {
	if (!hosted) {
		return {};
	}
	return (await readJson<{ finishedAt: Record<string, number> }>(join(sampleDir, "manifest.json")))?.finishedAt ?? {};
}

/** Every module-report.json under the results directory (test dirs, or test dirs inside a run's directory) */
async function scanModuleReports(): Promise<ModuleRecord[]> {
	const records: ModuleRecord[] = [];
	const times = await bundledTimes();
	const visit = async (dir: string, depth: number): Promise<void> => {
		const file = join(dir, "module-report.json");
		const report = await readJson<ModuleReport>(file);
		if (report) {
			const { mtimeMs } = await stat(file);
			const rel = relative(resultsDir, dir);
			records.push({ report, dir: rel, finishedAt: times[rel] ?? mtimeMs });
			return;
		}
		if (depth < 3) {
			await Promise.all((await subdirectories(dir)).map((d) => visit(d, depth + 1)));
		}
	};
	await Promise.all((await subdirectories(resultsDir)).map((d) => visit(d, 1)));
	return records;
}

let bundledRecords: Promise<ModuleRecord[]> | undefined;

/** Every module report: the test directories, and the rows of results.json that have none left */
export async function readModuleRecords(): Promise<ModuleRecord[]> {
	await connection();
	// the bundled results do not change while the server runs: scan them once
	const records = hosted ? [...(await (bundledRecords ??= scanModuleReports()))] : await scanModuleReports();
	const resultsPath = join(reportDir, "results.json");
	const known = new Set(records.map((r) => r.report.testId));
	for (const report of (await readJson<ModuleReport[]>(resultsPath)) ?? []) {
		if (!report.testId || !known.has(report.testId)) {
			// results.json has no times: older than anything with a directory
			records.push({ report, dir: null, finishedAt: 0 });
		}
	}
	return records.sort((a, b) => b.finishedAt - a.finishedAt);
}

export async function findModuleRecord(testId: string): Promise<ModuleRecord | null> {
	return (await readModuleRecords()).find((r) => r.report.testId === testId) ?? null;
}

/**
 * The CI project a record belongs to. Playwright ends each test directory's name with the project name
 * (`<spec>-<title>-<project>`); a plan run without a project is "conformance" (playwright.config.ts). Records
 * without a directory are matched on the plan and the project's variant values.
 */
export function recordInProject(record: ModuleRecord, project: ConformanceProject): boolean {
	if (record.report.plan !== project.plan) {
		return false;
	}
	if (record.dir) {
		const name = basename(record.dir);
		const owner = projects.filter((p) => name.endsWith(`-${p.name}`)).sort((a, b) => b.name.length - a.name.length)[0];
		return owner?.name === project.name;
	}
	const selectable = Object.keys(plans[project.plan]?.variants ?? {});
	const wanted = parseVariant(project.variant);
	return selectable.every((k) => wanted[k] == null || record.report.variant[k] === wanted[k]);
}

/** The key of a module's result: the module, and the module list when the plan runs it once per list */
export function moduleKey(testName: string, moduleList?: string | null): string {
	return moduleList ? `${testName} (${moduleList})` : testName;
}

/**
 * The latest record of each module of the plan (keyed by {@link moduleKey}: a module a plan runs once per module
 * list has one record per list); `filter` narrows the records (a project, a variant)
 */
export function latestByModule(
	plan: string,
	records: ModuleRecord[],
	filter: (r: ModuleRecord) => boolean = () => true,
): Map<string, ModuleRecord> {
	const latest = new Map<string, ModuleRecord>();
	for (const r of records) {
		// records are sorted newest first
		const key = moduleKey(r.report.testName, r.report.moduleList);
		if (r.report.plan === plan && !latest.has(key) && filter(r)) {
			latest.set(key, r);
		}
	}
	return latest;
}

/** One status per plan module, or per module list the module ran in; a module without a record once */
export function moduleStatuses(
	plan: string,
	latest: Map<string, ModuleRecord>,
	skip: Record<string, string> = {},
): ModuleStatus[] {
	const byName = new Map<string, ModuleRecord[]>();
	for (const r of latest.values()) {
		byName.set(r.report.testName, [...(byName.get(r.report.testName) ?? []), r]);
	}
	return (plans[plan]?.modules ?? []).flatMap((name): ModuleStatus[] => {
		const records = byName.get(name);
		if (!records) {
			return [{ name, record: null, skipReason: skip[name] }];
		}
		return records.map((record) => ({ name, moduleList: record.report.moduleList, record }));
	});
}

export function projectStatus(project: ConformanceProject, records: ModuleRecord[]): ProjectStatus {
	const latest = latestByModule(project.plan, records, (r) => recordInProject(r, project));
	const modules = moduleStatuses(project.plan, latest, project.skipModules);
	const counts = { ok: 0, failed: 0, notRun: 0 };
	let lastRunAt: number | null = null;
	for (const m of modules) {
		if (!m.record) {
			if (!m.skipReason) {
				counts.notRun++;
			}
			continue;
		}
		lastRunAt = Math.max(lastRunAt ?? 0, m.record.finishedAt);
		if (isOk(outcomeOf(m.record.report))) {
			counts.ok++;
		} else {
			counts.failed++;
		}
	}
	return { project, kind: planKind(project.plan), modules, counts, lastRunAt };
}

export async function projectStatuses(): Promise<ProjectStatus[]> {
	const records = await readModuleRecords();
	return projects.map((p) => projectStatus(p, records));
}

/** The files of a module's test directory */
export interface ModuleFiles {
	log: LogEntry[] | null;
	screenshots: string[];
	video: string | null;
	trace: string | null;
	logHtml: string | null;
	logJson: string | null;
	targetOutput: string | null;
}

export async function readModuleFiles(record: ModuleRecord): Promise<ModuleFiles> {
	const none: ModuleFiles = {
		log: null,
		screenshots: [],
		video: null,
		trace: null,
		logHtml: null,
		logJson: null,
		targetOutput: null,
	};
	const dir = record.dir == null ? null : inside(resultsDir, record.dir);
	if (!dir || !(await exists(dir))) {
		return none;
	}
	const names = await readdir(dir);
	const rel = (n: string) => (names.includes(n) ? join(record.dir ?? "", n) : null);
	return {
		log: await readJson<LogEntry[]>(join(dir, "log.json")),
		screenshots: names
			.filter((n) => n.endsWith(".png"))
			.sort()
			.map((n) => join(record.dir ?? "", n)),
		video: rel(names.find((n) => n.endsWith(".webm")) ?? "video.webm"),
		trace: rel("trace.zip"),
		// the bundled results keep log.html gzipped (the files route serves it as log.html)
		logHtml: rel(names.includes("log.html.gz") ? "log.html.gz" : "log.html")?.replace(/\.gz$/, "") ?? null,
		logJson: rel("log.json"),
		targetOutput: rel("target-output.txt"),
	};
}

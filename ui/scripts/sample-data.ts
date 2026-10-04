/**
 * Bundles a real report as the data of the hosted (read-only) UI, ui/sample-data/:
 *
 *   node --run sample-data               # from ui/: conformance-report/ and test-results/ of the repository root
 *   node scripts/sample-data.ts --report-dir <dir> --results-dir <dir> [--out sample-data]
 *
 * Produce the report with, for example (the output directory per project keeps the runs apart, as the UI does):
 *
 *   for p in rp-basic op-config op-dynamic; do
 *     CONFORMANCE_VIDEO=off CONFORMANCE_TRACE=off PLAYWRIGHT_TEST_OUTPUT_DIR=$PWD/test-results/$p/sample \
 *       node bin/cli.ts ci --project $p
 *   done
 *
 * What is kept of each module: module-report.json, log.json (minified), log.html (gzipped, served with
 * `content-encoding: gzip`), target-output.txt and the screenshots. Videos, traces and Playwright's `attachments`
 * copies are dropped. The result is a few MB. Besides the files, it writes
 *
 *   report/results.json, report/summary.md   the suite's reporter output
 *   report/ui-runs.json                      one finished run per project and run directory (the runs history)
 *   manifest.json                            when each module finished (file times do not survive a git checkout)
 */
import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";
import { gzipSync } from "node:zlib";
import { moduleName, outcomeOf } from "../lib/format.ts";
import type { ModuleReport, RunInfo } from "../lib/types.ts";
import { projects } from "../../src/runner/projects.ts";

const root = resolve(import.meta.dirname, "..", "..");
const { values: args } = parseArgs({
	options: {
		"report-dir": { type: "string", default: join(root, "conformance-report") },
		"results-dir": { type: "string", default: join(root, "test-results") },
		out: { type: "string", default: resolve(import.meta.dirname, "..", "sample-data") },
	},
});
const reportDir = resolve(args["report-dir"]);
const resultsDir = resolve(args["results-dir"]);
const out = resolve(args.out);

async function readJson<T>(path: string): Promise<T | null> {
	try {
		return JSON.parse(await readFile(path, "utf8")) as T;
	} catch {
		return null;
	}
}

/** Every directory under `dir` (up to `depth` levels) with a module-report.json */
async function moduleDirs(dir: string, depth = 3): Promise<string[]> {
	if (
		await stat(join(dir, "module-report.json")).then(
			() => true,
			() => false,
		)
	) {
		return [dir];
	}
	if (depth === 0) {
		return [];
	}
	const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
	const found = await Promise.all(
		entries
			.filter((e) => e.isDirectory() && e.name !== "attachments" && !e.name.startsWith("."))
			.map((e) => moduleDirs(join(dir, e.name), depth - 1)),
	);
	return found.flat();
}

/** The CI project whose name ends the test directory's name (the longest wins: `op-basic-dynamic` over `op-dynamic`) */
function projectOf(testDir: string): string {
	const name = basename(testDir);
	return (
		projects.filter((p) => name.endsWith(`-${p.name}`)).sort((a, b) => b.name.length - a.name.length)[0]?.name ??
		"conformance"
	);
}

const dirs = await moduleDirs(resultsDir);
if (dirs.length === 0) {
	throw new Error(`no module-report.json under ${resultsDir}: run a project first (see the top of this file)`);
}

await rm(out, { recursive: true, force: true });
await mkdir(join(out, "report"), { recursive: true });

const finishedAt: Record<string, number> = {};
const groups = new Map<string, { project: string; id: string; reports: { report: ModuleReport; at: number }[] }>();

for (const dir of dirs.sort()) {
	const rel = relative(resultsDir, dir);
	const target = join(out, "results", rel);
	await mkdir(target, { recursive: true });
	const reportFile = join(dir, "module-report.json");
	const report = (await readJson<ModuleReport>(reportFile))!;
	const at = (await stat(reportFile)).mtimeMs;
	finishedAt[rel] = Math.round(at);
	await cp(reportFile, join(target, "module-report.json"));
	const log = await readJson<unknown>(join(dir, "log.json"));
	if (log) {
		await writeFile(join(target, "log.json"), JSON.stringify(log));
	}
	const html = await readFile(join(dir, "log.html")).catch(() => null);
	if (html) {
		await writeFile(join(target, "log.html.gz"), gzipSync(html, { level: 9 }));
	}
	for (const name of await readdir(dir)) {
		if (name === "target-output.txt" || name.endsWith(".png")) {
			await cp(join(dir, name), join(target, name));
		}
	}
	// a run is the directory a module's test directory is in, when it has one of its own (<project>/<run id>/<test dir>)
	const parent = dirname(rel);
	const project = projectOf(dir);
	const key = parent === "." ? project : parent;
	const group = groups.get(key) ?? { project, id: basename(parent === "." ? "cli" : parent), reports: [] };
	group.reports.push({ report, at });
	groups.set(key, group);
}

for (const file of ["results.json", "summary.md"]) {
	await cp(join(reportDir, file), join(out, "report", file)).catch(() => undefined);
}

const runs: RunInfo[] = [...groups.entries()].map(([key, g]) => {
	const modules = g.reports
		.sort((a, b) => a.at - b.at)
		.map(({ report }) => ({
			title: report.title,
			name: moduleName(report.title),
			state: "done" as const,
			outcome: outcomeOf(report),
			durationMs: report.durationMs,
			testId: report.testId,
		}));
	const startedAt = Math.round(Math.min(...g.reports.map((r) => r.at - (r.report.durationMs ?? 0))));
	const endedAt = Math.round(Math.max(...g.reports.map((r) => r.at)));
	const failed = g.reports.some((r) => !r.report.ok);
	const stamp = new Date(startedAt).toISOString().replace(/\D/g, "").slice(0, 14);
	return {
		id: `${stamp}-${g.project}`,
		label: g.project,
		request: { kind: "project", project: g.project, options: { verbose: false, video: false, trace: false } },
		plan: g.reports[0].report.plan,
		variant: projects.find((p) => p.name === g.project)?.variant ?? "",
		command: `node bin/cli.ts ci --project ${g.project}`,
		outputDir: key,
		status: failed ? "failed" : "passed",
		startedAt,
		endedAt,
		exitCode: failed ? 1 : 0,
		modules,
	};
});
runs.sort((a, b) => b.startedAt - a.startedAt);
await writeFile(join(out, "report", "ui-runs.json"), JSON.stringify(runs, null, "\t"));
await writeFile(join(out, "manifest.json"), JSON.stringify({ generatedAt: Date.now(), finishedAt }, null, "\t"));

async function size(dir: string): Promise<number> {
	let total = 0;
	for (const e of await readdir(dir, { withFileTypes: true })) {
		total += e.isDirectory() ? await size(join(dir, e.name)) : (await stat(join(dir, e.name))).size;
	}
	return total;
}
console.log(
	`${out}: ${dirs.length} modules, ${runs.length} runs (${runs.map((r) => r.label).join(", ")}), ${(
		(await size(out)) / 1e6
	).toFixed(1)} MB`,
);

/**
 * Where the UI finds the suite and its results. All of it can be set with the environment (`openid-conformance ui`
 * sets it from its options):
 *
 *   CONFORMANCE_UI_ROOT      the suite's checkout (bin/cli.ts, src/runner/projects.ts); default: found upwards
 *                            from the working directory
 *   CONFORMANCE_REPORT_DIR   results.json / summary.md (the suite's reporter); default <root>/conformance-report
 *   CONFORMANCE_RESULTS_DIR  Playwright's output directory with each module's log.json, log.html,
 *                            module-report.json and screenshots; default <root>/test-results
 *   CONFORMANCE_UI_CWD       the directory runs start in (where a config's `target.command` runs); default <root>
 *
 * In hosted mode (mode.ts) the default report and results directories are the bundled ui/sample-data/report and
 * ui/sample-data/results; CONFORMANCE_UI_SAMPLE_DIR names another bundle, and CONFORMANCE_REPORT_DIR /
 * CONFORMANCE_RESULTS_DIR still win (a read-only view of any report).
 */
import { existsSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { hosted } from "./mode.ts";

function findRoot(): string {
	const fromEnv = process.env["CONFORMANCE_UI_ROOT"];
	if (fromEnv) {
		return resolve(fromEnv);
	}
	let dir = process.cwd();
	for (;;) {
		if (existsSync(join(dir, "bin", "cli.ts")) && existsSync(join(dir, "src", "runner", "projects.ts"))) {
			return dir;
		}
		const parent = dirname(dir);
		if (parent === dir) {
			// `next dev` in ui/: the suite is the parent directory
			return resolve(process.cwd(), "..");
		}
		dir = parent;
	}
}

export const suiteRoot = findRoot();

/**
 * ui/sample-data: next to the working directory (`next start` runs in ui/; on Vercel the function's directory is the
 * project's, ui/, inside the traced monorepo root), or in the checkout. Its files ship with the routes through
 * `outputFileTracingIncludes` (next.config.ts).
 */
function findSampleDir(): string {
	const candidates = [
		process.env["CONFORMANCE_UI_SAMPLE_DIR"],
		join(process.cwd(), "sample-data"),
		join(process.cwd(), "ui", "sample-data"),
		join(suiteRoot, "ui", "sample-data"),
	].filter((c): c is string => Boolean(c));
	return resolve(candidates.find((c) => existsSync(join(c, "manifest.json"))) ?? candidates[0]);
}

/** The bundled results (hosted mode), with `manifest.json` (when each module finished) */
export const sampleDir = findSampleDir();

export const reportDir = resolve(
	suiteRoot,
	process.env["CONFORMANCE_REPORT_DIR"] ?? (hosted ? join(sampleDir, "report") : "conformance-report"),
);

export const resultsDir = resolve(
	suiteRoot,
	process.env["CONFORMANCE_RESULTS_DIR"] ?? (hosted ? join(sampleDir, "results") : "test-results"),
);

export const runCwd = resolve(suiteRoot, process.env["CONFORMANCE_UI_CWD"] ?? ".");

export const cliPath = join(suiteRoot, "bin", "cli.ts");

/** `path` resolved inside `base`, or null when it would leave it (path traversal) */
export function inside(base: string, path: string): string | null {
	const full = resolve(base, path);
	const rel = relative(base, full);
	return rel === "" || rel.startsWith("..") || isAbsolute(rel) ? null : full;
}

/** A path for display: relative to the suite's checkout when inside it */
export function displayPath(path: string): string {
	const rel = relative(suiteRoot, path);
	return rel.startsWith("..") || isAbsolute(rel) ? path : rel || ".";
}

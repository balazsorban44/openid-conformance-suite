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
 */
import { existsSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

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

export const reportDir = resolve(suiteRoot, process.env["CONFORMANCE_REPORT_DIR"] ?? "conformance-report");

export const resultsDir = resolve(suiteRoot, process.env["CONFORMANCE_RESULTS_DIR"] ?? "test-results");

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

/**
 * Results of a conformance run: one {@link ModuleReport} per test module (attached by the fixtures as
 * `module-report.json`), collected by the Playwright reporter below (playwright.config.ts), which
 *   - prints one line per module as it finishes and a compact summary at the end (the console output),
 *   - writes conformance-report/results.json and summary.md and appends the markdown to $GITHUB_STEP_SUMMARY,
 *   - emits one `::error` annotation per unexpectedly failed module when `openid-conformance ci` runs on GitHub.
 *
 * Every module ends in exactly one {@link Outcome}. An expected failure (a failure the configuration's
 * expected-failures list names) is its own outcome, never "failed": "failed" is only what makes the run fail.
 */
import type { FullConfig, FullResult, Reporter, Suite, TestCase, TestResult } from "@playwright/test/reporter";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, sep } from "node:path";
import { stripVTControlCharacters, styleText } from "node:util";
import { emptyAnalysis, findings, type Finding, type ModuleAnalysis } from "./expected.ts";

/**
 * What a module did, as far as the run is concerned:
 * - `passed`, `review` (upstream REVIEW: a human looks at the log/screenshot), `skipped` (expected),
 *   `expected failure` / `expected warning` (the log has failures/warnings and all of them are in the
 *   configuration's expected-failures list): the run is fine,
 * - `failed`: something unexpected (a failure, a warning, a skip, an expected failure that did not happen, a crash).
 */
export type Outcome = "passed" | "review" | "skipped" | "expected failure" | "expected warning" | "failed";

/** One entry of results.json */
export interface ModuleReport {
	plan: string;
	testName: string;
	variant: Record<string, string>;
	variantString: string;
	testId: string;
	/** The module's lifecycle status: FINISHED, or INTERRUPTED when it stopped on an unexpected exception */
	status: string;
	/** The module's result as upstream computes it: PASSED, WARNING, REVIEW, SKIPPED, FAILED */
	result: string;
	/** True when nothing unexpected happened */
	ok: boolean;
	/** What the module did, in one word, see {@link Outcome} */
	outcome: Outcome;
	durationMs: number;
	analysis: ModuleAnalysis;
	/** Playwright test title, for cross-referencing the HTML report */
	title: string;
	/** The browser the suite drove (CONFORMANCE_BROWSER: chromium, firefox, webkit, chrome-mobile) */
	browser?: string;
	/** Paths of the attached log files (`log.html`, `log.json`) relative to the working directory, when known */
	attachments?: Record<string, string>;
	/** Why the module was skipped (the reason the test gave), when it was */
	skipReason?: string;
	/** The error of a test that stopped on an unexpected exception */
	error?: string;
}

export function outcomeOf(r: { result: string; ok: boolean; analysis: ModuleAnalysis }): Outcome {
	if (!r.ok) {
		return "failed";
	}
	if (r.analysis.expected_skip) {
		return "skipped";
	}
	switch (r.result) {
		case "PASSED":
			return "passed";
		case "REVIEW":
			return "review";
		case "SKIPPED":
			return "skipped";
		case "WARNING":
			return "expected warning";
		case "FAILED":
			return "expected failure";
		default:
			return "failed";
	}
}

const ICON: Record<Outcome, string> = {
	passed: "✅",
	review: "👀",
	skipped: "⏭️",
	"expected failure": "🟡",
	"expected warning": "🟡",
	failed: "❌",
};

/** Console glyphs: plain characters, coloured where the terminal supports it */
const GLYPH: Record<Outcome, { glyph: string; color: "green" | "cyan" | "gray" | "yellow" | "red" }> = {
	passed: { glyph: "✓", color: "green" },
	review: { glyph: "?", color: "cyan" },
	skipped: { glyph: "-", color: "gray" },
	"expected failure": { glyph: "~", color: "yellow" },
	"expected warning": { glyph: "~", color: "yellow" },
	failed: { glyph: "✗", color: "red" },
};

/** The order outcomes are counted in: what needs attention first */
const OUTCOMES: Outcome[] = ["failed", "passed", "expected failure", "expected warning", "review", "skipped"];

/** "20 passed, 3 skipped, 1 expected failure" (failed first, zero counts left out) */
export function countOutcomes(reports: ModuleReport[], separator = ", "): string {
	return OUTCOMES.map((o) => [o, reports.filter((r) => r.outcome === o).length] as const)
		.filter(([, n]) => n > 0)
		.map(([o, n]) => `${n} ${o}`)
		.join(separator);
}

/** The findings that make a module fail (expected failures and warnings are not problems) */
function problemsOf(r: ModuleReport): Finding[] {
	return findings(r.analysis).filter((f) => f.kind !== "expected failure" && f.kind !== "expected warning");
}

/** One problem as one line of text; `q` quotes condition names (markdown code, or nothing) */
function problemText(f: Finding, q: string, maxMessage: number): string {
	switch (f.kind) {
		case "unexpected failure":
			return `${q}${f.ref.src}${q}${f.ref.current_block ? ` in "${f.ref.current_block}"` : ""}${f.ref.msg ? `: ${truncate(f.ref.msg, maxMessage)}` : ""}`;
		case "unexpected warning":
			return `warning ${q}${f.ref.src}${q}${f.ref.msg ? `: ${truncate(f.ref.msg, maxMessage)}` : ""}`;
		case "unexpected skip":
			return "the module was skipped, which the configuration does not expect";
		case "expected skip did not happen":
			return "the module was expected to be skipped but ran";
		default:
			return `${f.kind}: ${q}${"ref" in f ? f.ref.src : ""}${q}`;
	}
}

/** Why a failed module failed, one text per problem (a crash without findings: its error) */
export function failureReasons(r: ModuleReport, q = "", maxMessage = 300): string[] {
	const reasons = problemsOf(r).map((f) => problemText(f, q, maxMessage));
	if (reasons.length === 0 && r.error) {
		reasons.push(truncate(stripVTControlCharacters(r.error), maxMessage));
	}
	return reasons;
}

/** What a module that did not simply pass has to say: the expected conditions, the skip reason */
function noteOf(r: ModuleReport, q: string): string {
	switch (r.outcome) {
		case "expected failure":
		case "expected warning": {
			const refs = [...r.analysis.expected_failures, ...r.analysis.expected_warnings].map((c) => `${q}${c.src}${q}`);
			return [...new Set(refs)].join(", ");
		}
		case "skipped":
			return r.skipReason ? truncate(r.skipReason, 200) : "";
		case "review":
			return "manual review";
		default:
			return "";
	}
}

function truncate(s: string, n: number): string {
	s = s.replace(/\s+/g, " ");
	return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function cell(s: string): string {
	return s.replace(/\|/g, "\\|");
}

/** "0.8s", "12s", "1m05s" */
export function formatDuration(ms: number): string {
	if (ms < 10_000) {
		return `${(ms / 1000).toFixed(1)}s`;
	}
	const s = Math.round(ms / 1000);
	return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m${String(s % 60).padStart(2, "0")}s`;
}

/**
 * The variant most modules of a plan share (per parameter, the value most of them have; printed once under the plan)
 * and, for a module, the parameters where it deviates (a module that does not have a parameter does not deviate).
 */
function planVariant(rs: ModuleReport[]): { shared: string; deviations: (r: ModuleReport) => string } {
	const mode = new Map<string, string>();
	for (const k of new Set(rs.flatMap((r) => Object.keys(r.variant)))) {
		const counts = Map.groupBy(
			rs.flatMap((r) => (r.variant[k] == null ? [] : [r.variant[k]])),
			(v) => v,
		);
		mode.set(k, [...counts].sort((a, b) => b[1].length - a[1].length)[0]?.[0] ?? "");
	}
	return {
		shared: [...mode]
			.sort(([a], [b]) => a.localeCompare(b))
			.map(([k, v]) => `[${k}=${v}]`)
			.join(""),
		deviations: (r) =>
			Object.entries(r.variant)
				.filter(([k, v]) => v !== mode.get(k))
				.map(([k, v]) => `${k}=${v}`)
				.join(" "),
	};
}

/**
 * Markdown for one run (written to $GITHUB_STEP_SUMMARY and conformance-report/summary.md): one short section per
 * run, so the sections of a workflow run's jobs read one after the other. Unexpected failures come first, then per
 * plan what is not a plain pass (expected failures, skips, reviews) and the passed modules as a list.
 *
 * `artifact` is the name of the uploaded artifact that holds the logs, `reportUrl` the page it can be found on.
 */
export function renderSummaryMarkdown(
	reports: ModuleReport[],
	opts: { title?: string; reportUrl?: string; artifact?: string; durationMs?: number } = {},
): string {
	const failed = reports.filter((r) => r.outcome === "failed");
	const duration = opts.durationMs ?? reports.reduce((sum, r) => sum + r.durationMs, 0);
	const counts = countOutcomes(reports, " · ").replace(/^(\d+ failed)/, "**$1**");
	const title = opts.title ?? "OpenID conformance results";
	const lines = [
		`### ${failed.length > 0 ? ICON.failed : ICON.passed} ${title} · ${reports.length === 0 ? "no modules ran" : `${counts} · ${formatDuration(duration)}`}`,
		"",
	];

	for (const r of failed) {
		const reasons = failureReasons(r, "`");
		lines.push(`- **\`${r.testName}\`**${reasons.length === 1 ? ` — ${reasons[0]}` : ""}`);
		if (reasons.length > 1) {
			lines.push(...reasons.slice(0, 5).map((t) => `  - ${t}`));
			if (reasons.length > 5) {
				lines.push(`  - … and ${reasons.length - 5} more`);
			}
		}
		const files = ["log.html", "video", "trace"]
			.filter((name) => r.attachments?.[name])
			.map((name) => `${name === "log.html" ? "log" : name}: \`${r.attachments?.[name]}\``);
		if (files.length > 0) {
			lines.push(`  - ${files.join(", ")}${artifactNote(opts)}`);
		}
	}
	if (failed.length > 0) {
		lines.push("");
	}

	// everything else stays out of the way: one collapsed block per run
	const noted = reports.filter((r) => r.outcome !== "passed" && r.outcome !== "failed");
	if (reports.length > 0) {
		lines.push(
			`<details><summary>${reports.length} modules${noted.length > 0 ? ` (${noted.length} skipped, review or expected)` : ""}</summary>`,
			"",
		);
		for (const [plan, rs] of Map.groupBy(reports, (r) => r.plan)) {
			const { shared, deviations } = planVariant(rs);
			lines.push(`**${plan}**${shared ? ` \`${shared}\`` : ""}`, "");
			const notedHere = rs.filter((r) => r.outcome !== "passed" && r.outcome !== "failed");
			if (notedHere.length > 0) {
				const variantColumn = notedHere.some((r) => deviations(r) !== "");
				lines.push(
					`| Module | Result |${variantColumn ? " Variant differs |" : ""} Note |`,
					`|---|---|${variantColumn ? "---|" : ""}---|`,
				);
				for (const r of notedHere) {
					lines.push(
						`| \`${r.testName}\` | ${ICON[r.outcome]} ${r.outcome} |${variantColumn ? ` ${cell(deviations(r))} |` : ""} ${cell(noteOf(r, "`"))} |`,
					);
				}
				lines.push("");
			}
			const passed = rs.filter((r) => r.outcome === "passed");
			if (passed.length > 0) {
				lines.push(`${ICON.passed} ${passed.map((r) => `\`${r.testName}\``).join(", ")}`, "");
			}
		}
		lines.push("</details>", "");
	}
	return lines.join("\n");
}

function artifactNote(opts: { reportUrl?: string; artifact?: string }): string {
	if (!opts.artifact) {
		return "";
	}
	return opts.reportUrl
		? ` in the artifact [\`${opts.artifact}\`](${opts.reportUrl})`
		: ` in the artifact \`${opts.artifact}\``;
}

/** The console line of a module: `<glyph> <module>  <duration>  <what is noteworthy>` (name padded to `width`) */
export function renderConsoleLine(r: ModuleReport, width: number, colors = false): string {
	const { glyph, color } = GLYPH[r.outcome];
	const note = consoleNote(r);
	return `${colors ? styleText(color, glyph) : glyph} ${r.testName.padEnd(width)}  ${formatDuration(r.durationMs).padStart(6)}${note ? `  ${note}` : ""}`;
}

function consoleNote(r: ModuleReport): string {
	const note = noteOf(r, "");
	switch (r.outcome) {
		case "passed":
			return "";
		case "failed":
			return "FAILED";
		case "review":
			return "review";
		default:
			return note ? `${r.outcome}: ${truncate(note, 100)}` : r.outcome;
	}
}

/**
 * What is printed after the last module: the counts and, for each unexpected failure, the condition, its message
 * and block, and where the log is.
 */
export function renderConsoleSummary(reports: ModuleReport[], durationMs: number): string {
	const failed = reports.filter((r) => r.outcome === "failed");
	const lines = [
		"",
		`${failed.length > 0 ? "FAILED" : "OK"}: ${countOutcomes(reports) || "no modules ran"} (${formatDuration(durationMs)})`,
	];
	for (const r of failed) {
		lines.push("", `✗ ${r.testName}`, ...failureReasons(r).map((t) => `    ${t}`));
		const log = r.attachments?.["log.html"];
		if (log) {
			lines.push(`    log: ${log}`);
		}
	}
	return lines.join("\n");
}

function escapeData(s: string): string {
	return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function escapeProperty(s: string): string {
	return escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

/** The workflow command (GitHub Actions) `::error file=...,line=...,title=...::message` for a failed module */
export function githubErrorAnnotation(r: ModuleReport, location?: { file: string; line: number }): string {
	const reasons = failureReasons(r);
	const message = reasons.length > 1 ? `${reasons[0]} (and ${reasons.length - 1} more)` : (reasons[0] ?? "failed");
	const props = [
		...(location ? [`file=${escapeProperty(location.file)}`, `line=${location.line}`] : []),
		`title=${escapeProperty(r.testName)}`,
	];
	return `::error ${props.join(",")}::${escapeData(message)}`;
}

/**
 * Playwright reporter: collects the per-module reports the fixtures attach after each test (tests/fixtures.ts,
 * attachment `module-report.json`), prints the console output and writes
 *   conformance-report/results.json  - machine readable, one {@link ModuleReport} per module
 *   conformance-report/summary.md    - human/agent readable; also appended to $GITHUB_STEP_SUMMARY
 *
 * Environment: CONFORMANCE_REPORT_DIR, CONFORMANCE_SUMMARY_TITLE (default: the project or plan, and the browser
 * when it is not chromium), CONFORMANCE_BROWSER,
 * CONFORMANCE_ARTIFACT (name of the uploaded artifact with the logs), CONFORMANCE_ANNOTATIONS=1 (set by
 * `openid-conformance ci`: on GitHub Actions, one `::error` per unexpectedly failed module).
 */
export default class ConformanceReporter implements Reporter {
	private reports: ModuleReport[] = [];
	private outDir = "conformance-report";
	private title = "OpenID conformance";
	private browser = "chromium";
	private width = 0;
	private colors = false;
	private annotate = false;
	private workspace = process.cwd();

	onBegin(_config: FullConfig, suite: Suite): void {
		const env = process.env;
		this.outDir = env["CONFORMANCE_REPORT_DIR"] ?? "conformance-report";
		mkdirSync(this.outDir, { recursive: true });
		this.browser = env["CONFORMANCE_BROWSER"] || "chromium";
		this.title =
			env["CONFORMANCE_SUMMARY_TITLE"] ??
			(env["CONFORMANCE_PROJECT"] ?? env["CONFORMANCE_PLAN"] ?? this.title) +
				(this.browser === "chromium" ? "" : ` (${this.browser})`);
		this.colors = process.stdout.isTTY === true && !env["NO_COLOR"];
		this.annotate = env["GITHUB_ACTIONS"] === "true" && env["CONFORMANCE_ANNOTATIONS"] === "1";
		this.workspace = env["GITHUB_WORKSPACE"] ?? process.cwd();
		const tests = suite.allTests();
		this.width = Math.max(0, ...tests.map((t) => moduleName(t).length));
		process.stdout.write(`${this.title}: ${tests.length} module${tests.length === 1 ? "" : "s"}\n`);
	}

	onTestEnd(test: TestCase, result: TestResult): void {
		const r = this.reportOf(test, result);
		if (!r) {
			return;
		}
		this.reports.push(r);
		process.stdout.write(renderConsoleLine(r, this.width, this.colors) + "\n");
		if (r.outcome === "failed" && this.annotate) {
			const file = relative(this.workspace, test.location.file).split(sep).join("/");
			// a file outside the workspace (the suite used as an action) cannot be annotated
			const location = file.startsWith("..") ? undefined : { file, line: test.location.line };
			process.stdout.write(githubErrorAnnotation(r, location) + "\n");
		}
	}

	private reportOf(test: TestCase, result: TestResult): ModuleReport | undefined {
		const title = test.titlePath().slice(1).join(" › ");
		// titlePath: ["", project, spec file, the plan's describe, ..., test title]
		const path = test.titlePath();
		const plan = path.length > 4 ? (path[3] ?? "") : "";
		const att = result.attachments.find((a) => a.name === "module-report.json");
		const body = att?.body ?? (att?.path && existsSync(att.path) ? readFileSync(att.path) : undefined);
		let r: ModuleReport;
		if (body) {
			r = JSON.parse(body.toString("utf8")) as ModuleReport;
			r.title = title;
			r.durationMs = result.duration;
			// the error of a test that failed on findings repeats them; keep it for the ones that crashed
			if (result.status !== "passed" && result.status !== "skipped" && !r.error && result.error?.message) {
				r.error = stripVTControlCharacters(result.error.message);
			}
		} else if (result.status === "failed" || result.status === "timedOut") {
			r = {
				plan,
				testName: moduleName(test),
				variant: {},
				variantString: "",
				testId: "",
				status: "INTERRUPTED",
				result: "UNKNOWN",
				ok: false,
				outcome: "failed",
				durationMs: result.duration,
				analysis: emptyAnalysis(),
				title,
				error: stripVTControlCharacters(result.error?.message ?? result.status),
			};
		} else if (result.status === "skipped") {
			// skipped before the module ran (a project's skipModules): nothing was attached
			r = {
				plan,
				testName: moduleName(test),
				variant: {},
				variantString: "",
				testId: "",
				status: "FINISHED",
				result: "SKIPPED",
				ok: true,
				outcome: "skipped",
				durationMs: result.duration,
				analysis: { ...emptyAnalysis(), ok: true },
				title,
			};
		} else {
			return undefined;
		}
		r.browser = this.browser;
		const skip = test.annotations.find((a) => a.type === "skip" && a.description);
		if (r.outcome === "skipped" && skip?.description) {
			r.skipReason = skip.description;
		}
		const files: Record<string, string> = {};
		for (const a of result.attachments) {
			if (a.path && (a.name === "log.html" || a.name === "log.json")) {
				// the HTML reporter copies attachments to <test dir>/attachments/<name>-<hash>; point at the original
				const dir = basename(dirname(a.path)) === "attachments" ? dirname(dirname(a.path)) : dirname(a.path);
				files[a.name] = relative(process.cwd(), join(dir, a.name)).split(sep).join("/");
			}
		}
		if (Object.keys(files).length > 0) {
			r.attachments = files;
		}
		return r;
	}

	onStdOut(chunk: string | Buffer): void {
		process.stdout.write(chunk);
	}

	onStdErr(chunk: string | Buffer): void {
		process.stderr.write(chunk);
	}

	onError(error: { message?: string; stack?: string }): void {
		process.stderr.write(stripVTControlCharacters(error.message ?? error.stack ?? String(error)) + "\n");
	}

	onEnd(result: FullResult): void {
		const env = process.env;
		const resultsPath = join(this.outDir, "results.json");
		// merge with results written by other shards / projects in the same directory
		let existing: ModuleReport[] = [];
		try {
			existing = JSON.parse(readFileSync(resultsPath, "utf8")) as ModuleReport[];
		} catch {
			// missing or unreadable
		}
		const merged = [...existing.filter((e) => !this.reports.some((r) => r.title === e.title)), ...this.reports];
		writeFileSync(resultsPath, JSON.stringify(merged, null, 2));
		const runUrl =
			env["GITHUB_SERVER_URL"] && env["GITHUB_REPOSITORY"] && env["GITHUB_RUN_ID"]
				? `${env["GITHUB_SERVER_URL"]}/${env["GITHUB_REPOSITORY"]}/actions/runs/${env["GITHUB_RUN_ID"]}#artifacts`
				: undefined;
		const md = renderSummaryMarkdown(this.reports, {
			title: this.title,
			durationMs: result.duration,
			artifact: env["CONFORMANCE_ARTIFACT"],
			reportUrl: runUrl,
		});
		writeFileSync(join(this.outDir, "summary.md"), md);
		const stepSummary = env["GITHUB_STEP_SUMMARY"];
		if (stepSummary) {
			appendFileSync(stepSummary, md + "\n");
		}
		process.stdout.write(renderConsoleSummary(this.reports, result.duration) + "\n");
	}

	printsToStdio(): boolean {
		return true;
	}
}

/** Test titles are "<module>: <what the OP/RP must do>" */
function moduleName(test: TestCase): string {
	return test.title.split(":")[0] ?? test.title;
}

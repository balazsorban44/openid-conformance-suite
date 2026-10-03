/**
 * Results of a conformance run: one {@link ModuleReport} per test module (attached by the fixtures as
 * `module-report.json`), collected by the Playwright reporter below (playwright.config.ts) into
 * conformance-report/results.json and summary.md (also appended to $GITHUB_STEP_SUMMARY).
 */
import type { Reporter, TestCase, TestResult } from "@playwright/test/reporter";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { emptyAnalysis, findings, type Finding, type ModuleAnalysis } from "./expected.ts";

/** One line of results.json / the summary table */
export interface ModuleReport {
	plan: string;
	testName: string;
	variant: Record<string, string>;
	variantString: string;
	testId: string;
	status: string;
	result: string;
	ok: boolean;
	durationMs: number;
	analysis: ModuleAnalysis;
	/** Playwright test title, for cross-referencing the HTML report */
	title: string;
	/** Relative paths of attachments (log.html etc.) when known */
	attachments?: Record<string, string>;
	error?: string;
}

const RESULT_ICON: Record<string, string> = {
	PASSED: "✅",
	WARNING: "⚠️",
	REVIEW: "👀",
	SKIPPED: "⏭️",
	FAILED: "❌",
	UNKNOWN: "❓",
	INTERRUPTED: "💥",
};

export function resultIcon(result: string, ok: boolean): string {
	if (!ok && result !== "FAILED") {
		return "❌";
	}
	return RESULT_ICON[result] ?? "❓";
}

/**
 * GitHub-flavoured markdown summary for one or more plans (written to $GITHUB_STEP_SUMMARY and
 * conformance-report/summary.md). Human and agent readable: one table per plan, then the failing conditions.
 */
export function renderSummaryMarkdown(
	reports: ModuleReport[],
	opts: { title?: string; reportUrl?: string } = {},
): string {
	const okCount = reports.filter((r) => r.ok).length;
	const lines = [
		`## ${opts.title ?? "OpenID conformance results"}`,
		"",
		`**${okCount}/${reports.length} modules OK** (${countBy(reports)})${opts.reportUrl ? ` · [full report](${opts.reportUrl})` : ""}`,
		"",
	];
	for (const [plan, rs] of Map.groupBy(reports, (r) => r.plan)) {
		lines.push(
			`### ${plan}`,
			"",
			"| | Module | Variant | Result | Conditions (ok/warn/fail) | Notes |",
			"|---|---|---|---|---|---|",
		);
		for (const r of rs) {
			const a = r.analysis;
			const notes = findings(a).map(note);
			if (r.error) {
				notes.push(`💥 ${truncate(r.error, 200)}`);
			}
			lines.push(
				`| ${resultIcon(r.result, r.ok)} | \`${r.testName}\` | ${r.variantString ? `\`${r.variantString}\`` : ""} | ${r.result}${r.status === "INTERRUPTED" ? " (interrupted)" : ""} | ${a.counts.SUCCESS}/${a.counts.WARNING}/${a.counts.FAILURE} | ${notes.join("<br>")} |`,
			);
		}
		lines.push("");
	}
	return lines.join("\n");
}

function note(f: Finding): string {
	switch (f.kind) {
		case "unexpected failure":
			return `❌ \`${f.ref.src}\`${f.ref.current_block ? ` in "${f.ref.current_block}"` : ""}${f.ref.msg ? `: ${truncate(f.ref.msg, 160)}` : ""}`;
		case "unexpected warning":
			return `⚠️ \`${f.ref.src}\`${f.ref.msg ? `: ${truncate(f.ref.msg, 120)}` : ""}`;
		case "expected failure":
		case "expected warning":
			return `(${f.kind}) \`${f.ref.src}\``;
		case "expected failure did not happen":
		case "expected warning did not happen":
			return `❌ ${f.kind}: \`${f.ref.src}\``;
		case "unexpected skip":
		case "expected skip did not happen":
			return `❌ ${f.kind}`;
	}
}

function countBy(reports: ModuleReport[]): string {
	const c = new Map<string, number>();
	for (const r of reports) {
		const key = r.ok ? r.result : "FAILED";
		c.set(key, (c.get(key) ?? 0) + 1);
	}
	return [...c.entries()].map(([k, v]) => `${v} ${k.toLowerCase()}`).join(", ");
}

function truncate(s: string, n: number): string {
	s = s.replace(/\s+/g, " ").replace(/\|/g, "\\|");
	return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/**
 * Playwright reporter that collects the per-module reports attached by tests/plan.spec.ts (attachment
 * `module-report.json`) and writes:
 *   conformance-report/results.json  - machine readable
 *   conformance-report/summary.md    - human/agent readable; also appended to $GITHUB_STEP_SUMMARY
 */
export default class ConformanceReporter implements Reporter {
	private reports: ModuleReport[] = [];
	private outDir = "conformance-report";

	onBegin(): void {
		this.outDir = process.env["CONFORMANCE_REPORT_DIR"] ?? "conformance-report";
		mkdirSync(this.outDir, { recursive: true });
	}

	onTestEnd(test: TestCase, result: TestResult): void {
		const title = test.titlePath().slice(1).join(" › ");
		const att = result.attachments.find((a) => a.name === "module-report.json");
		const body = att?.body ?? (att?.path && existsSync(att.path) ? readFileSync(att.path) : undefined);
		if (body) {
			const r = JSON.parse(body.toString("utf8")) as ModuleReport;
			r.title = title;
			if (result.status !== "passed" && result.status !== "skipped" && !r.error && result.error?.message) {
				r.error = result.error.message;
			}
			this.reports.push(r);
		} else if (result.status === "failed" || result.status === "timedOut") {
			this.reports.push({
				plan: test.titlePath()[1] ?? "",
				testName: test.title,
				variant: {},
				variantString: "",
				testId: "",
				status: "INTERRUPTED",
				result: "UNKNOWN",
				ok: false,
				durationMs: result.duration,
				analysis: emptyAnalysis(),
				title,
				error: result.error?.message ?? result.status,
			});
		}
	}

	onEnd(): void {
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
		const md = renderSummaryMarkdown(this.reports, {
			title: process.env["CONFORMANCE_SUMMARY_TITLE"] ?? "OpenID conformance results",
		});
		writeFileSync(join(this.outDir, "summary.md"), md);
		const stepSummary = process.env["GITHUB_STEP_SUMMARY"];
		if (stepSummary) {
			appendFileSync(stepSummary, md + "\n");
		}
		if (process.env["CI"] || process.env["CONFORMANCE_PRINT_SUMMARY"]) {
			process.stdout.write("\n" + md + "\n");
		}
	}

	printsToStdio(): boolean {
		return false;
	}
}

import type { FullConfig, FullResult, Reporter, TestCase, TestResult } from "@playwright/test/reporter";
import { mkdirSync, writeFileSync, appendFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { renderSummaryMarkdown, type ModuleReport } from "./report.ts";

/**
 * Playwright reporter that collects the per-module reports attached by tests/plan.spec.ts (attachment
 * `module-report.json`) and writes:
 *   conformance-report/results.json  - machine readable
 *   conformance-report/summary.md    - human/agent readable; also appended to $GITHUB_STEP_SUMMARY
 */
export default class ConformanceReporter implements Reporter {
	private reports: ModuleReport[] = [];
	private outDir = "conformance-report";

	onBegin(config: FullConfig): void {
		void config;
		this.outDir = process.env["CONFORMANCE_REPORT_DIR"] ?? "conformance-report";
		mkdirSync(this.outDir, { recursive: true });
	}

	onTestEnd(test: TestCase, result: TestResult): void {
		const att = result.attachments.find((a) => a.name === "module-report.json");
		const body = att?.body ?? (att?.path && existsSync(att.path) ? readFileSync(att.path) : undefined);
		if (body) {
			const r = JSON.parse(body.toString("utf8")) as ModuleReport;
			r.title = test.titlePath().slice(1).join(" › ");
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
				analysis: {
					expected_failures: [],
					unexpected_failures: [],
					expected_failures_did_not_happen: [],
					expected_warnings: [],
					unexpected_warnings: [],
					expected_warnings_did_not_happen: [],
					expected_skip: false,
					unexpected_skip: false,
					expected_skip_did_not_happen: false,
					counts: { SUCCESS: 0, WARNING: 0, FAILURE: 0 },
					ok: false,
				},
				title: test.titlePath().slice(1).join(" › "),
				error: result.error?.message ?? result.status,
			});
		}
	}

	onEnd(result: FullResult): void {
		void result;
		const resultsPath = join(this.outDir, "results.json");
		// merge with results written by other shards / projects in the same directory
		let existing: ModuleReport[] = [];
		if (existsSync(resultsPath)) {
			try {
				existing = JSON.parse(readFileSync(resultsPath, "utf8")) as ModuleReport[];
			} catch {
				existing = [];
			}
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

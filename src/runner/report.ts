import type { LogEntry } from "../framework/EventLog.ts";
import { escapeHtml } from "../framework/views.ts";
import type { ModuleAnalysis } from "./expected.ts";

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
export function renderSummaryMarkdown(reports: ModuleReport[], opts: { title?: string; reportUrl?: string } = {}): string {
	const lines: string[] = [];
	const total = reports.length;
	const okCount = reports.filter((r) => r.ok).length;
	lines.push(`## ${opts.title ?? "OpenID conformance results"}`);
	lines.push("");
	lines.push(`**${okCount}/${total} modules OK** (${countBy(reports)})${opts.reportUrl ? ` · [full report](${opts.reportUrl})` : ""}`);
	lines.push("");
	const byPlan = new Map<string, ModuleReport[]>();
	for (const r of reports) {
		byPlan.set(r.plan, [...(byPlan.get(r.plan) ?? []), r]);
	}
	for (const [plan, rs] of byPlan) {
		lines.push(`### ${plan}`);
		lines.push("");
		lines.push("| | Module | Variant | Result | Conditions (ok/warn/fail) | Notes |");
		lines.push("|---|---|---|---|---|---|");
		for (const r of rs) {
			const a = r.analysis;
			const notes: string[] = [];
			for (const f of a.unexpected_failures) {
				notes.push(`❌ \`${f.src}\`${f.current_block ? ` in "${f.current_block}"` : ""}${f.msg ? `: ${truncate(f.msg, 160)}` : ""}`);
			}
			for (const f of a.unexpected_warnings) {
				notes.push(`⚠️ \`${f.src}\`${f.msg ? `: ${truncate(f.msg, 120)}` : ""}`);
			}
			for (const f of a.expected_failures) {
				notes.push(`(expected failure) \`${f.src}\``);
			}
			for (const f of a.expected_warnings) {
				notes.push(`(expected warning) \`${f.src}\``);
			}
			for (const f of a.expected_failures_did_not_happen) {
				notes.push(`❌ expected failure did not happen: \`${f.src}\``);
			}
			for (const f of a.expected_warnings_did_not_happen) {
				notes.push(`❌ expected warning did not happen: \`${f.src}\``);
			}
			if (a.unexpected_skip) {
				notes.push("❌ unexpected skip");
			}
			if (a.expected_skip_did_not_happen) {
				notes.push("❌ expected skip did not happen");
			}
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
 * Render the event log of one module as a self-contained HTML page, in the spirit of the upstream
 * log-detail.html: one row per entry, coloured by result, with expandable details.
 */
export function renderLogHtml(title: string, entries: LogEntry[], extra: { result: string; status: string; variant: Record<string, string> }): string {
	const rows: string[] = [];
	const blockColours = new Map<string, string>();
	for (const e of entries) {
		const { _id, testId, src, time, seq, ...rest } = e;
		void _id;
		void testId;
		void seq;
		const result = typeof rest["result"] === "string" ? (rest["result"] as string) : "";
		const blockId = typeof rest["blockId"] === "string" ? (rest["blockId"] as string) : null;
		if (blockId && rest["startBlock"] === true) {
			blockColours.set(blockId, "#" + blockId);
		}
		const msg = typeof rest["msg"] === "string" ? (rest["msg"] as string) : "";
		delete rest["msg"];
		delete rest["result"];
		delete rest["blockId"];
		const details = Object.keys(rest).length > 0 ? `<details><summary>details</summary><pre>${escapeHtml(JSON.stringify(rest, replacer, 2))}</pre></details>` : "";
		const img = typeof rest["img"] === "string" ? `<img src="${escapeHtml(rest["img"])}" style="max-width:600px;display:block">` : "";
		rows.push(
			`<tr class="r-${result || "none"}"${blockId ? ` style="border-left:8px solid #${blockId}"` : ""}><td class="t">${new Date(time).toISOString().slice(11, 23)}</td><td class="src">${escapeHtml(src)}</td><td class="res">${escapeHtml(result)}</td><td class="msg">${escapeHtml(msg)}${img}${details}</td></tr>`,
		);
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>
body{font-family:system-ui,sans-serif;font-size:13px;margin:16px}
table{border-collapse:collapse;width:100%}td{vertical-align:top;padding:4px 6px;border-bottom:1px solid #eee}
td.t{white-space:nowrap;color:#888}td.src{white-space:nowrap;font-family:monospace}td.res{white-space:nowrap;font-weight:bold}
tr.r-SUCCESS td.res{color:#1a7f37}tr.r-FAILURE{background:#ffebe9}tr.r-FAILURE td.res{color:#cf222e}
tr.r-WARNING{background:#fff8c5}tr.r-WARNING td.res{color:#9a6700}tr.r-INFO td.res{color:#0969da}tr.r-REVIEW{background:#ddf4ff}
pre{white-space:pre-wrap;word-break:break-all;background:#f6f8fa;padding:6px;max-height:400px;overflow:auto}
details{margin-top:4px}summary{cursor:pointer;color:#0969da}
</style></head><body>
<h1>${escapeHtml(title)}</h1>
<p><b>Result:</b> ${escapeHtml(extra.result)} · <b>Status:</b> ${escapeHtml(extra.status)} · <b>Variant:</b> <code>${escapeHtml(JSON.stringify(extra.variant))}</code> · ${entries.length} log entries</p>
<table>${rows.join("\n")}</table>
</body></html>`;
}

function replacer(_k: string, v: unknown): unknown {
	if (typeof v === "string" && v.startsWith("data:image/") && v.length > 200) {
		return v.slice(0, 60) + "…(image omitted)";
	}
	return v;
}

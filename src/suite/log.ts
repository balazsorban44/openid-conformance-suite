/**
 * The per-test event log: the same entries upstream writes to MongoDB (EventLog.java / TestInstanceEventLog.java):
 * `_id`, `testId`, `src`, `time`, `seq`, then the logged fields (`msg`, `result`, `requirements`, `blockId`, ...).
 * Blocks (upstream `startBlock`) are `-START-BLOCK-` entries; every entry logged while a block is open carries its
 * `blockId`.
 *
 * The current test's log is reached through {@link currentLog}: the `op`/`rp` fixtures install it with
 * {@link useLog} for the duration of a test (Playwright runs one test at a time per worker), and
 * {@link withContext} scopes overrides (e.g. `soft()`'s severity) to a call with AsyncLocalStorage.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes, randomInt } from "node:crypto";

export type Result = "SUCCESS" | "INFO" | "WARNING" | "FAILURE" | "REVIEW";

export interface LogEntry {
	_id: string;
	testId: string;
	src: string;
	time: number;
	seq: number;
	[key: string]: unknown;
}

export type LogFields = Record<string, unknown>;

export interface EventLog {
	readonly testId: string;
	readonly entries: LogEntry[];
	/** The open block's id (a six digit hex colour, as upstream), or null */
	readonly blockId: string | null;
	log(src: string, fields: LogFields | string): LogEntry;
	/** Opens a block (closing any open one) and logs its `-START-BLOCK-` entry; returns the block id */
	startBlock(msg: string): string;
	endBlock(): void;
	/** Merges `update` into the REVIEW entry created for `placeholder` (upstream ImageService.fillPlaceholder) */
	fillPlaceholder(placeholder: string, update: LogFields): LogEntry | null;
	/** Placeholders (REVIEW entries with `upload`) that have no image yet */
	remainingPlaceholders(): string[];
}

let seq = 0;

export function createLog(testId = randomBytes(6).toString("hex"), sink?: (e: LogEntry) => void): EventLog {
	const entries: LogEntry[] = [];
	let blockId: string | null = null;
	const log: EventLog = {
		testId,
		entries,
		get blockId() {
			return blockId;
		},
		log(src, fields) {
			const map: LogFields = typeof fields === "string" ? { msg: fields } : fields;
			seq++;
			const entry: LogEntry = { _id: `${testId}-${seq}`, testId, src, time: Date.now(), seq };
			for (const [k, v] of Object.entries(map)) {
				if (v !== undefined) {
					entry[k] = sanitise(v);
				}
			}
			if (blockId != null && entry["blockId"] === undefined) {
				entry["blockId"] = blockId;
			}
			entries.push(entry);
			sink?.(entry);
			return entry;
		},
		startBlock(msg) {
			// a random six-character hex string that the HTML log uses as a CSS colour
			blockId = randomInt(256 * 256 * 256)
				.toString(16)
				.padStart(6, "0");
			log.log("-START-BLOCK-", { msg, startBlock: true });
			return blockId;
		},
		endBlock() {
			blockId = null;
		},
		fillPlaceholder(placeholder, update) {
			const entry = entries.find((e) => e["upload"] === placeholder);
			if (!entry) {
				return null;
			}
			Object.assign(entry, sanitise(update) as LogFields);
			return entry;
		},
		remainingPlaceholders() {
			return entries.filter((e) => typeof e["upload"] === "string" && e["img"] == null).map((e) => String(e["upload"]));
		},
	};
	return log;
}

/** Make a logged value JSON-safe: Sets become arrays, Errors their message, Maps/Headers objects, Dates ISO strings */
export function sanitise(v: unknown): unknown {
	if (v instanceof Set || Array.isArray(v)) {
		return [...v].map(sanitise);
	}
	if (v instanceof Map || v instanceof Headers) {
		return sanitise(Object.fromEntries(v));
	}
	if (v instanceof Error) {
		return v.message;
	}
	if (v instanceof URLSearchParams) {
		return v.toString();
	}
	if (typeof v === "bigint") {
		return Number(v);
	}
	if (typeof v === "object" && v !== null) {
		if (typeof (v as { toJSON?: unknown }).toJSON === "function") {
			return (v as { toJSON: () => unknown }).toJSON();
		}
		const out: LogFields = {};
		for (const [k, x] of Object.entries(v)) {
			out[k] = sanitise(x);
		}
		return out;
	}
	return v;
}

/** How a failing check is recorded: upstream's ConditionResult for callAndContinueOnFailure / onFail */
export type Severity = "failure" | "warning" | "info";

export interface TestContext {
	log: EventLog;
	/** The test module name, the `src` of the module's own entries (e.g. "oidcc-server") */
	testName: string;
	/** Severity a failing check records (set by soft()) */
	severity: Severity;
	/** Runs a named step (Playwright test.step in a conformance test; a plain call elsewhere) */
	step: <T>(name: string, fn: () => Promise<T>) => Promise<T>;
}

const scoped = new AsyncLocalStorage<TestContext>();
let installed: TestContext | null = null;

/**
 * Installs `log` as the current test's log until the returned function is called. Fixtures call this; a
 * Playwright worker runs one test at a time, so one installed context per process is enough.
 */
export function useLog(log: EventLog, opts: Partial<Omit<TestContext, "log">> = {}): () => void {
	const previous = installed;
	installed = {
		log,
		testName: opts.testName ?? "TEST",
		severity: opts.severity ?? "failure",
		step: opts.step ?? ((_name, fn) => fn()),
	};
	return () => {
		installed = previous;
	};
}

/** The current context (throws when no test is running: checks must run inside a test or {@link useLog}) */
export function currentContext(): TestContext {
	const ctx = scoped.getStore() ?? installed;
	if (!ctx) {
		throw new Error("No conformance test is running: install a log with useLog() (the op/rp fixtures do)");
	}
	return ctx;
}

export function currentLog(): EventLog {
	return currentContext().log;
}

/** Runs `fn` with parts of the current context replaced (AsyncLocalStorage: also applies to awaited work) */
export function withContext<T>(override: Partial<TestContext>, fn: () => T): T {
	return scoped.run({ ...currentContext(), ...override }, fn);
}

/** The overall result of a module's log, as upstream computes the test result from the condition results */
export function resultOf(entries: LogEntry[], skipped = false): "PASSED" | "WARNING" | "REVIEW" | "FAILED" | "SKIPPED" {
	// a placeholder the test no longer needs (the OP redirected instead of showing an error page) is not REVIEW
	const results = new Set(entries.filter((e) => e["image_no_longer_required"] !== true).map((e) => e["result"]));
	if (results.has("FAILURE")) {
		return "FAILED";
	}
	if (skipped) {
		return "SKIPPED";
	}
	if (results.has("WARNING")) {
		return "WARNING";
	}
	if (results.has("REVIEW")) {
		return "REVIEW";
	}
	return "PASSED";
}

/**
 * Renders a module's log as a self-contained HTML page in the spirit of upstream's log-detail.html: one row per
 * entry, coloured by result, with expandable details.
 */
export function renderLogHtml(
	title: string,
	entries: LogEntry[],
	extra: { result: string; status: string; variant: Record<string, string> },
): string {
	const rows: string[] = [];
	for (const e of entries) {
		const { _id: _, testId: _testId, seq: _seq, src, time, ...rest } = e;
		const result = typeof rest["result"] === "string" ? rest["result"] : "";
		const blockId = typeof rest["blockId"] === "string" ? rest["blockId"] : null;
		const msg = typeof rest["msg"] === "string" ? rest["msg"] : "";
		delete rest["msg"];
		delete rest["result"];
		delete rest["blockId"];
		const details =
			Object.keys(rest).length > 0
				? `<details><summary>details</summary><pre>${escapeHtml(JSON.stringify(rest, omitImages, 2))}</pre></details>`
				: "";
		const img =
			typeof rest["img"] === "string"
				? `<img src="${escapeHtml(rest["img"])}" style="max-width:600px;display:block">`
				: "";
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

export function escapeHtml(s: unknown): string {
	return String(s)
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

function omitImages(_k: string, v: unknown): unknown {
	if (typeof v === "string" && v.startsWith("data:image/") && v.length > 200) {
		return v.slice(0, 60) + "…(image omitted)";
	}
	return v;
}

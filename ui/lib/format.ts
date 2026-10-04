/** Client-safe helpers: outcomes, variants, durations and times */
import type { ModuleReport, ModuleStatus, Outcome, StripModule } from "./types.ts";

/** What a refused run says in the hosted (read-only) UI: the run buttons' tooltip and the API's 405 (lib/mode.ts) */
export const HOSTED_RUN_MESSAGE = "runs need a local checkout: pnpm ui";

/** The UI outcome of a module report: an expected failure is fine, anything the analysis did not expect is not */
export function outcomeOf(r: Pick<ModuleReport, "result" | "ok" | "status">): Outcome {
	if (!r.ok) {
		return r.status === "INTERRUPTED" ? "interrupted" : "failed";
	}
	switch (r.result) {
		case "PASSED":
			return "passed";
		case "WARNING":
			return "warning";
		case "REVIEW":
			return "review";
		case "SKIPPED":
			return "skipped";
		case "FAILED":
			return "expected-failure";
		default:
			return "failed";
	}
}

export const OUTCOME_LABEL: Record<Outcome, string> = {
	passed: "Passed",
	warning: "Warning",
	review: "Review",
	skipped: "Skipped",
	"expected-failure": "Expected failure",
	failed: "Failed",
	interrupted: "Interrupted",
	"not-run": "Not run",
	pending: "Pending",
	running: "Running",
	cancelled: "Cancelled",
};

/** Outcomes that count as a module being fine */
export function isOk(o: Outcome): boolean {
	return o === "passed" || o === "warning" || o === "review" || o === "skipped" || o === "expected-failure";
}

/** "[k=v][k2=v2]" -> { k: v, k2: v2 } (tests/fixtures.ts parseVariant) */
export function parseVariant(s: string): Record<string, string> {
	return Object.fromEntries([...s.matchAll(/\[([^=\]]+)=([^\]]*)\]/g)].map((m) => [m[1], m[2]]));
}

/** { k: v } -> "[k=v]..." sorted by name (tests/fixtures.ts variantString) */
export function variantString(v: Record<string, string>): string {
	return Object.keys(v)
		.sort()
		.map((k) => `[${k}=${v[k]}]`)
		.join("");
}

/** The module of a test title: "oidcc-server: ..." -> "oidcc-server" (tests/fixtures.ts moduleName) */
export function moduleName(title: string): string {
	return title.split(":")[0].trim();
}

/** What the module checks: the title after the module name */
export function moduleIntent(title: string): string {
	const i = title.indexOf(":");
	return i < 0 ? "" : title.slice(i + 1).trim();
}

/** The glob of CONFORMANCE_MODULE (src/suite/config.ts globBody: `*` and `?`) */
export function globMatch(glob: string, name: string): boolean {
	const body = [...glob].map((c) => (c === "*" ? ".*" : c === "?" ? "." : c.replace(/[.+^${}()|[\]\\]/g, "\\$&")));
	return new RegExp(`^${body.join("")}$`).test(name);
}

export function formatDuration(ms: number | undefined): string {
	if (ms == null) {
		return "";
	}
	if (ms < 1000) {
		return `${Math.round(ms)} ms`;
	}
	const s = ms / 1000;
	if (s < 60) {
		return `${s.toFixed(s < 10 ? 1 : 0)} s`;
	}
	const m = Math.floor(s / 60);
	return `${m} min ${Math.round(s - m * 60)} s`;
}

export function formatRelative(at: number | null | undefined, now = Date.now()): string {
	if (at == null) {
		return "never";
	}
	if (at === 0) {
		// a row of results.json whose test directory is gone: no time recorded
		return "earlier";
	}
	const s = Math.round((now - at) / 1000);
	if (s < 45) {
		return "just now";
	}
	const m = Math.round(s / 60);
	if (m < 60) {
		return `${m} min ago`;
	}
	const h = Math.round(m / 60);
	if (h < 24) {
		return `${h} h ago`;
	}
	const d = Math.round(h / 24);
	return d === 1 ? "yesterday" : `${d} days ago`;
}

export function formatTime(at: number): string {
	return new Date(at).toISOString().slice(11, 23);
}

export function formatDateTime(at: number): string {
	return new Date(at).toLocaleString("en-GB", {
		year: "numeric",
		month: "short",
		day: "numeric",
		hour: "2-digit",
		minute: "2-digit",
	});
}

/** URL of a file in the results directory (served by app/api/files) */
export function fileUrl(path: string): string {
	return `/api/files/results/${path.split("/").map(encodeURIComponent).join("/")}`;
}

/** The squares of the module strip for a plan's or project's modules */
export function stripModules(modules: ModuleStatus[]): StripModule[] {
	return modules.map((m): StripModule => {
		if (m.record) {
			return { name: m.name, outcome: outcomeOf(m.record.report), testId: m.record.report.testId || undefined };
		}
		return m.skipReason
			? { name: m.name, outcome: "skipped", note: "not run by this project" }
			: { name: m.name, outcome: "not-run" };
	});
}

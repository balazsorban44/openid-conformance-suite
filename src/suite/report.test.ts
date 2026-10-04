import { expect, test } from "vitest";
import { emptyAnalysis, type ConditionRef, type ModuleAnalysis } from "./expected.ts";
import {
	countOutcomes,
	displayName,
	duplicateNames,
	formatDuration,
	githubErrorAnnotation,
	outcomeOf,
	renderConsoleLine,
	renderConsoleSummary,
	renderSummaryMarkdown,
	type ModuleReport,
} from "./report.ts";

const base = { client_registration: "dynamic_client", response_type: "code", server_metadata: "discovery" };

function report(
	testName: string,
	result: string,
	analysis: Partial<ModuleAnalysis> = {},
	extra: Partial<ModuleReport> = {},
): ModuleReport {
	const a: ModuleAnalysis = { ...emptyAnalysis(), counts: { SUCCESS: 20, WARNING: 0, FAILURE: 0 }, ...analysis };
	const ok = a.ok;
	const r = {
		plan: "oidcc-dynamic-certification-test-plan",
		testName,
		variant: { ...base, client_auth_type: "private_key_jwt" },
		variantString: "",
		testId: "x",
		status: "FINISHED",
		result,
		ok,
		durationMs: 800,
		analysis: a,
		title: `${testName}: x`,
		...extra,
	};
	return { ...r, outcome: outcomeOf({ result, ok, analysis: a }) };
}

const rotateRef: ConditionRef = {
	current_block: "Verify new keys",
	src: "VerifyNewJwksHasNewSigningKey",
	msg: "same keys",
};
const badRef: ConditionRef = {
	current_block: "Check the id_token",
	src: "EnsureIdTokenContainsKid",
	msg: "id_token header | has no kid\nsecond line",
};

const passed = report("oidcc-idtoken-rs256", "PASSED", { ok: true });
const skipped = report(
	"oidcc-idtoken-unsigned",
	"SKIPPED",
	{ ok: true, expected_skip: true },
	{ skipReason: "OP does not support none" },
);
const review = report("oidcc-ensure-redirect-uri-in-authorization-request", "REVIEW", { ok: true });
const expectedFailure = report(
	"oidcc-server-rotate-keys",
	"FAILED",
	{ ok: true, expected_failures: [rotateRef], counts: { SUCCESS: 20, WARNING: 0, FAILURE: 1 } },
	{ variant: { ...base, client_auth_type: "client_secret_basic" }, durationMs: 3200 },
);
const failed = report(
	"oidcc-idtoken-kid",
	"FAILED",
	{ ok: false, unexpected_failures: [badRef], counts: { SUCCESS: 20, WARNING: 0, FAILURE: 1 } },
	{ attachments: { "log.html": "test-results/oidcc-idtoken-kid/log.html" } },
);

test("an expected failure is its own outcome, not 'failed'", () => {
	expect(expectedFailure.outcome).toBe("expected failure");
	expect(expectedFailure.ok).toBe(true);
	expect(failed.outcome).toBe("failed");
	expect([passed, skipped, review].map((r) => r.outcome)).toEqual(["passed", "skipped", "review"]);
	// a module that ended FAILED because the configuration expects it to be skipped is a skip
	expect(outcomeOf({ result: "FAILED", ok: true, analysis: { ...emptyAnalysis(), expected_skip: true } })).toBe(
		"skipped",
	);
	expect(outcomeOf({ result: "WARNING", ok: true, analysis: emptyAnalysis() })).toBe("expected warning");
	// an unknown result is never fine
	expect(outcomeOf({ result: "UNKNOWN", ok: true, analysis: emptyAnalysis() })).toBe("failed");
});

test("counts name the expected failure and never call it failed", () => {
	const all = [passed, passed, skipped, review, expectedFailure];
	expect(countOutcomes(all)).toBe("2 passed, 1 expected failure, 1 review, 1 skipped");
	expect(countOutcomes([failed, ...all])).toBe("1 failed, 2 passed, 1 expected failure, 1 review, 1 skipped");
});

test("summary of a run without unexpected failures: one line, the rest collapsed", () => {
	const md = renderSummaryMarkdown([passed, skipped, review, expectedFailure], {
		title: "op-dynamic",
		durationMs: 72_000,
	});
	expect(md).toBe(
		[
			"### ✅ op-dynamic · 1 passed · 1 expected failure · 1 review · 1 skipped · 1m12s",
			"",
			"<details><summary>4 modules (3 skipped, review or expected)</summary>",
			"",
			"**oidcc-dynamic-certification-test-plan** `[client_auth_type=private_key_jwt][client_registration=dynamic_client][response_type=code][server_metadata=discovery]`",
			"",
			"| Module | Result | Variant differs | Note |",
			"|---|---|---|---|",
			"| `oidcc-idtoken-unsigned` | ⏭️ skipped |  | OP does not support none |",
			"| `oidcc-ensure-redirect-uri-in-authorization-request` | 👀 review |  | manual review |",
			"| `oidcc-server-rotate-keys` | 🟡 expected failure | client_auth_type=client_secret_basic | `VerifyNewJwksHasNewSigningKey` |",
			"",
			"✅ `oidcc-idtoken-rs256`",
			"",
			"</details>",
			"",
		].join("\n"),
	);
	expect(md).not.toMatch(/failed|❌/);
});

test("the variant is printed once when every module has it, and the table has no variant column", () => {
	const md = renderSummaryMarkdown([passed, report("b", "REVIEW", { ok: true })], { title: "t" });
	expect(md).toContain("`[client_auth_type=private_key_jwt][client_registration=dynamic_client]");
	expect(md).toContain("| Module | Result | Note |");
	expect(md).not.toContain("private_key_jwt |");
});

test("a module that does not have a variant parameter does not deviate; only real differences are listed", () => {
	const noRegistration = report(
		"c",
		"REVIEW",
		{ ok: true },
		{ variant: { response_type: "code", server_metadata: "discovery" } },
	);
	const md = renderSummaryMarkdown([passed, passed, review, noRegistration], { title: "t" });
	expect(md).toContain("| Module | Result | Note |");
	expect(md).not.toContain("undefined");
});

test("an unexpected failure is first, with condition, block, message and the log", () => {
	const md = renderSummaryMarkdown([passed, expectedFailure, failed], {
		title: "op-dynamic",
		artifact: "conformance-op-dynamic",
		reportUrl: "https://github.com/o/r/actions/runs/1#artifacts",
	});
	const lines = md.split("\n");
	expect(lines[0]).toBe("### ❌ op-dynamic · **1 failed** · 1 passed · 1 expected failure · 4.8s");
	expect(lines[0]).not.toContain("OK");
	// the failure comes before the collapsed module list
	expect(lines.findIndex((l) => l.startsWith("- **`oidcc-idtoken-kid`**"))).toBeLessThan(
		lines.findIndex((l) => l.startsWith("<details>")),
	);
	expect(md).toContain(
		'- **`oidcc-idtoken-kid`** — `EnsureIdTokenContainsKid` in "Check the id_token": id_token header | has no kid second line',
	);
	expect(md).toContain(
		"  - log: `test-results/oidcc-idtoken-kid/log.html` in the artifact [`conformance-op-dynamic`](https://github.com/o/r/actions/runs/1#artifacts)",
	);
	// the failed module is not repeated in the plan's table; the expected failure is
	expect(md).not.toContain("| `oidcc-idtoken-kid`");
	expect(md).toContain("🟡 expected failure");
});

test("a crash without findings shows its error; several problems are a list", () => {
	const crashed = report(
		"oidcc-crash",
		"UNKNOWN",
		{ ok: false },
		{ status: "INTERRUPTED", error: "\u001b[31mTimeout of 240000ms exceeded\u001b[39m" },
	);
	expect(renderSummaryMarkdown([crashed])).toContain("- **`oidcc-crash`** — Timeout of 240000ms exceeded");
	const many = report("oidcc-many", "FAILED", {
		ok: false,
		unexpected_failures: [badRef],
		unexpected_warnings: [{ current_block: "", src: "CheckW", msg: "warned" }],
		expected_failures_did_not_happen: [rotateRef],
	});
	const md = renderSummaryMarkdown([many]);
	expect(md).toContain("- **`oidcc-many`**\n  - `EnsureIdTokenContainsKid` in");
	expect(md).toContain("  - warning `CheckW`: warned");
	expect(md).toContain("  - expected failure did not happen: `VerifyNewJwksHasNewSigningKey`");
});

test("console lines: one per module, a note only where there is something to say", () => {
	const w = "oidcc-ensure-redirect-uri-in-authorization-request".length;
	expect(renderConsoleLine(passed, w)).toBe(`✓ ${"oidcc-idtoken-rs256".padEnd(w)}    0.8s`);
	expect(renderConsoleLine(skipped, 22)).toBe("- oidcc-idtoken-unsigned    0.8s  skipped: OP does not support none");
	expect(renderConsoleLine(review, 0)).toMatch(/^\? oidcc-ensure.*  review$/);
	expect(renderConsoleLine(expectedFailure, 24)).toBe(
		"~ oidcc-server-rotate-keys    3.2s  expected failure: VerifyNewJwksHasNewSigningKey",
	);
	expect(renderConsoleLine(failed, 0)).toMatch(/^✗ oidcc-idtoken-kid {2}\s+0\.8s {2}FAILED$/);
});

test("console summary: OK without failures, otherwise the failures with condition, message and log", () => {
	expect(renderConsoleSummary([passed, skipped, expectedFailure], 65_000)).toBe(
		"\nOK: 1 passed, 1 expected failure, 1 skipped (1m05s)",
	);
	expect(renderConsoleSummary([passed, failed], 2000)).toBe(
		[
			"",
			"FAILED: 1 failed, 1 passed (2.0s)",
			"",
			"✗ oidcc-idtoken-kid",
			'    EnsureIdTokenContainsKid in "Check the id_token": id_token header | has no kid second line',
			"    log: test-results/oidcc-idtoken-kid/log.html",
		].join("\n"),
	);
});

test("GitHub annotation: one ::error with the spec location, escaped", () => {
	expect(githubErrorAnnotation(failed, { file: "tests/op/dynamic.spec.ts", line: 136 })).toBe(
		'::error file=tests/op/dynamic.spec.ts,line=136,title=oidcc-idtoken-kid::EnsureIdTokenContainsKid in "Check the id_token": id_token header | has no kid second line',
	);
	const two = report("a:b,c", "FAILED", {
		ok: false,
		unexpected_failures: [{ current_block: "", src: "X", msg: "100%" }, badRef],
	});
	expect(githubErrorAnnotation(two)).toBe("::error title=a%3Ab%2Cc::X: 100%25 (and 1 more)");
});

test("durations", () => {
	expect([0, 800, 9_960, 12_400, 59_600, 65_000, 3_600_000].map(formatDuration)).toEqual([
		"0.0s",
		"0.8s",
		"10.0s",
		"12s",
		"1m00s",
		"1m05s",
		"60m00s",
	]);
});

test("a module a plan runs for several variants is named with its instance in the console and the summary", () => {
	const hybrid = (responseType: string, ok: boolean) =>
		report(
			"oidcc-server",
			ok ? "PASSED" : "FAILED",
			{ ok },
			{ instance: `response_type=${responseType}`, variant: { ...base, response_type: responseType } },
		);
	const codeIdToken = hybrid("code id_token", true);
	const codeToken = hybrid("code token", false);
	const alone = report("oidcc-codereuse", "PASSED", { ok: true }, { instance: "response_type=code token" });
	const duplicates = duplicateNames([codeIdToken, codeToken, alone].map((r) => r.testName));
	expect(displayName(codeIdToken, duplicates)).toBe("oidcc-server (response_type=code id_token)");
	expect(displayName(alone, duplicates)).toBe("oidcc-codereuse");
	expect(renderConsoleLine(codeIdToken, 0, false, displayName(codeIdToken, duplicates))).toBe(
		"✓ oidcc-server (response_type=code id_token)    0.8s",
	);
	const md = renderSummaryMarkdown([codeIdToken, codeToken, alone]);
	expect(md).toContain("- **`oidcc-server (response_type=code token)`**");
	expect(md).toContain("`oidcc-server (response_type=code id_token)`, `oidcc-codereuse`");
	expect(renderConsoleSummary([codeIdToken, codeToken], 1000)).toContain("✗ oidcc-server (response_type=code token)");
});

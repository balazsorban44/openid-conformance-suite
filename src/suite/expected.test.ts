import { expect, test } from "vitest";
import type { LogEntry } from "./log.ts";
import { fnmatch, type ExpectedFailure, type ExpectedSkip } from "./config.ts";
import { analyzeResultLogs, describeProblems, emptyAnalysis } from "./expected.ts";

function entry(src: string, result: string | undefined, extra: Record<string, unknown> = {}): LogEntry {
	return { _id: "x", testId: "t", src, time: 0, seq: 0, result, ...extra };
}

test("fnmatch", () => {
	expect(fnmatch("oidcc-*", "oidcc-server")).toBe(true);
	expect(fnmatch("oidcc-*", "fapi-server")).toBe(false);
	expect(fnmatch("authlete-*.json", "authlete-oidcc.json")).toBe(true);
});

test("expected failure inside a block is matched; unexpected ones reported", () => {
	const logs: LogEntry[] = [
		entry("-START-BLOCK-", undefined, { startBlock: true, blockId: "abc", msg: "Testing something" }),
		entry("EnsureHttpStatusCodeIs4xx", "FAILURE", { blockId: "abc" }),
		entry("CheckState", "WARNING"),
		entry("Fine", "SUCCESS"),
	];
	const a = analyzeResultLogs(
		"oidcc-codereuse-30seconds",
		{ response_type: "code" },
		"FAILED",
		logs,
		[
			{
				"test-name": "oidcc-codereuse-30seconds",
				variant: "*",
				"configuration-filename": "*.json",
				"current-block": "Testing something",
				condition: "EnsureHttpStatusCodeIs4xx",
				"expected-result": "failure",
			},
		],
		[],
		"my.json",
	);
	expect(a.expected_failures.length).toBe(1);
	expect(a.unexpected_failures.length).toBe(0);
	expect(a.unexpected_warnings.length).toBe(1);
	expect(a.counts).toEqual({ SUCCESS: 1, WARNING: 1, FAILURE: 1 });
	expect(a.ok).toBe(false);
});

test("expected failure that does not happen is reported; variant subset matching", () => {
	const a = analyzeResultLogs(
		"oidcc-server",
		{ response_type: "code", client_auth_type: "none" },
		"PASSED",
		[entry("Fine", "SUCCESS")],
		[
			{
				"test-name": "oidcc-server",
				variant: { response_type: "code" },
				"configuration-filename": "*",
				"current-block": "*",
				condition: "Nope",
				"expected-result": "failure",
			},
			{
				"test-name": "oidcc-server",
				variant: { response_type: "id_token" },
				"configuration-filename": "*",
				"current-block": "*",
				condition: "Other",
				"expected-result": "failure",
			},
		],
		[],
		"x.json",
	);
	expect(a.expected_failures_did_not_happen.length).toBe(1);
	expect(a.ok).toBe(false);
});

test("describeProblems lists what fails the module, not expected failures", () => {
	const a = emptyAnalysis();
	a.unexpected_failures.push({ current_block: "Block", src: "A", msg: "boom" });
	a.unexpected_warnings.push({ current_block: "", src: "B", msg: "hmm" });
	a.expected_failures.push({ current_block: "", src: "C", msg: "expected" });
	a.expected_warnings_did_not_happen.push({ current_block: "*", src: "D" });
	a.unexpected_skip = true;
	expect(describeProblems(a)).toEqual([
		"FAILURE A [Block]: boom",
		"WARNING B: hmm",
		"expected warning did not happen: D",
		"module was unexpectedly SKIPPED",
	]);
});

function failure(extra: Partial<ExpectedFailure> = {}): ExpectedFailure {
	return {
		"test-name": "m",
		variant: "*",
		"configuration-filename": "*",
		"current-block": "*",
		condition: "Cond",
		"expected-result": "failure",
		...extra,
	};
}

test('current-block "*" matches inside and outside blocks; a named block only inside it', () => {
	const logs: LogEntry[] = [
		entry("Cond", "FAILURE"),
		entry("-START-BLOCK-", undefined, { startBlock: true, blockId: "b1", msg: "Block one" }),
		entry("Cond", "FAILURE", { blockId: "b1" }),
		entry("Cond", "FAILURE", { blockId: "unknown" }),
	];
	const star = analyzeResultLogs("m", {}, "FAILED", logs, [failure()], [], "c.json");
	expect(star.expected_failures.map((r) => r.current_block)).toEqual(["", "Block one", ""]);
	expect(star.ok).toBe(true);

	const named = analyzeResultLogs("m", {}, "FAILED", logs, [failure({ "current-block": "Block one" })], [], "c.json");
	expect(named.expected_failures).toEqual([{ current_block: "Block one", src: "Cond", msg: undefined }]);
	expect(named.unexpected_failures.map((r) => r.current_block)).toEqual(["", ""]);
	expect(named.ok).toBe(false);
});

test("configuration-filename and test-name globs; variant subset", () => {
	const logs = [entry("Cond", "FAILURE")];
	const run = (f: ExpectedFailure, variant: Record<string, string> = {}) =>
		analyzeResultLogs("oidcc-server", variant, "FAILED", logs, [f], [], "oidc-provider-basic.json");
	expect(run(failure({ "test-name": "oidcc-*", "configuration-filename": "oidc-provider-*.json" })).ok).toBe(true);
	expect(run(failure({ "test-name": "oidcc-*", "configuration-filename": "other-*.json" })).ok).toBe(false);
	expect(run(failure({ "test-name": "oidcc-server-*" })).ok).toBe(false);
	expect(run(failure({ "test-name": "oidcc-server", "configuration-filename": "" })).ok).toBe(true);
	const v = { "test-name": "oidcc-server", variant: { a: "1" } };
	expect(run(failure(v), { a: "1", b: "2" }).ok).toBe(true);
	expect(run(failure(v), { b: "2" }).ok).toBe(false);
});

test("warnings, result mismatch, counts and ok", () => {
	const logs = [
		entry("Warn", "WARNING", { msg: "w" }),
		entry("Cond", "WARNING", { msg: "a warning where a failure is expected" }),
		entry("Info", "INFO"),
		entry("Review", "REVIEW"),
		entry("NoResult", undefined),
	];
	const a = analyzeResultLogs(
		"m",
		{},
		"WARNING",
		logs,
		[failure({ condition: "Warn", "expected-result": "warning" }), failure()],
		[],
		"c.json",
	);
	expect(a.expected_warnings).toEqual([{ current_block: "", src: "Warn", msg: "w" }]);
	expect(a.unexpected_warnings).toEqual([
		{ current_block: "", src: "Cond", msg: "a warning where a failure is expected" },
	]);
	expect(a.expected_failures_did_not_happen).toEqual([{ current_block: "*", src: "Cond" }]);
	expect(a.counts).toEqual({ SUCCESS: 0, WARNING: 2, FAILURE: 0 });
	expect(a.ok).toBe(false);

	const passed = analyzeResultLogs("m", {}, "PASSED", [entry("Ok", "SUCCESS")], [], [], "c.json");
	expect(passed.ok).toBe(true);
	for (const result of ["UNKNOWN", "RUNNING", ""]) {
		expect(analyzeResultLogs("m", {}, result, [], [], [], "c.json").ok, result).toBe(false);
	}
	expect(analyzeResultLogs("m", {}, "REVIEW", [], [], [], "c.json").ok).toBe(true);
});

test("expected skips: FAILED counts as skipped; a skip that did not happen fails", () => {
	const skip: ExpectedSkip = { "test-name": "m", variant: "*", "configuration-filename": "c.json" };
	const failed = analyzeResultLogs("m", {}, "FAILED", [entry("X", "FAILURE")], [], [skip], "c.json");
	expect(failed.expected_skip).toBe(true);
	expect(failed.unexpected_failures.length).toBe(1); // the failure itself is still unexpected
	expect(failed.ok).toBe(false);
	const passed = analyzeResultLogs("m", {}, "PASSED", [], [], [skip], "c.json");
	expect(passed.expected_skip_did_not_happen).toBe(true);
	expect(passed.ok).toBe(false);
	const otherConfig = analyzeResultLogs("m", {}, "SKIPPED", [], [], [skip], "d.json");
	expect(otherConfig.unexpected_skip).toBe(true);
	expect(otherConfig.ok).toBe(false);
});

test("unexpected skip and expected skip", () => {
	const skipped = analyzeResultLogs("m", {}, "SKIPPED", [], [], [], "c.json");
	expect(skipped.unexpected_skip).toBe(true);
	const expected = analyzeResultLogs(
		"m",
		{},
		"SKIPPED",
		[],
		[],
		[{ "test-name": "m", variant: "*", "configuration-filename": "*" }],
		"c.json",
	);
	expect(expected.ok).toBe(true);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import type { LogEntry } from "../framework/EventLog.ts";
import type { ExpectedFailure, ExpectedSkip } from "./config.ts";
import { analyzeResultLogs, describeProblems, emptyAnalysis } from "./expected.ts";
import { fnmatch } from "./glob.ts";

function entry(src: string, result: string | undefined, extra: Record<string, unknown> = {}): LogEntry {
	return { _id: "x", testId: "t", src, time: 0, seq: 0, result, ...extra };
}

test("fnmatch", () => {
	assert.ok(fnmatch("oidcc-*", "oidcc-server"));
	assert.ok(!fnmatch("oidcc-*", "fapi-server"));
	assert.ok(fnmatch("authlete-*.json", "authlete-oidcc.json"));
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
	assert.equal(a.expected_failures.length, 1);
	assert.equal(a.unexpected_failures.length, 0);
	assert.equal(a.unexpected_warnings.length, 1);
	assert.deepEqual(a.counts, { SUCCESS: 1, WARNING: 1, FAILURE: 1 });
	assert.equal(a.ok, false);
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
	assert.equal(a.expected_failures_did_not_happen.length, 1);
	assert.equal(a.ok, false);
});

test("describeProblems lists what fails the module, not expected failures", () => {
	const a = emptyAnalysis();
	a.unexpected_failures.push({ current_block: "Block", src: "A", msg: "boom" });
	a.unexpected_warnings.push({ current_block: "", src: "B", msg: "hmm" });
	a.expected_failures.push({ current_block: "", src: "C", msg: "expected" });
	a.expected_warnings_did_not_happen.push({ current_block: "*", src: "D" });
	a.unexpected_skip = true;
	assert.deepEqual(describeProblems(a), [
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
	assert.deepEqual(
		star.expected_failures.map((r) => r.current_block),
		["", "Block one", ""],
	);
	assert.equal(star.ok, true);

	const named = analyzeResultLogs("m", {}, "FAILED", logs, [failure({ "current-block": "Block one" })], [], "c.json");
	assert.deepEqual(named.expected_failures, [{ current_block: "Block one", src: "Cond", msg: undefined }]);
	assert.deepEqual(
		named.unexpected_failures.map((r) => r.current_block),
		["", ""],
	);
	assert.equal(named.ok, false);
});

test("configuration-filename and test-name globs; variant subset", () => {
	const logs = [entry("Cond", "FAILURE")];
	const run = (f: ExpectedFailure, variant: Record<string, string> = {}) =>
		analyzeResultLogs("oidcc-server", variant, "FAILED", logs, [f], [], "oidc-provider-basic.json");
	assert.equal(run(failure({ "test-name": "oidcc-*", "configuration-filename": "oidc-provider-*.json" })).ok, true);
	assert.equal(run(failure({ "test-name": "oidcc-*", "configuration-filename": "other-*.json" })).ok, false);
	assert.equal(run(failure({ "test-name": "oidcc-server-*" })).ok, false);
	assert.equal(run(failure({ "test-name": "oidcc-server", "configuration-filename": "" })).ok, true);
	const v = { "test-name": "oidcc-server", variant: { a: "1" } };
	assert.equal(run(failure(v), { a: "1", b: "2" }).ok, true);
	assert.equal(run(failure(v), { b: "2" }).ok, false);
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
	assert.deepEqual(a.expected_warnings, [{ current_block: "", src: "Warn", msg: "w" }]);
	assert.deepEqual(a.unexpected_warnings, [
		{ current_block: "", src: "Cond", msg: "a warning where a failure is expected" },
	]);
	assert.deepEqual(a.expected_failures_did_not_happen, [{ current_block: "*", src: "Cond" }]);
	assert.deepEqual(a.counts, { SUCCESS: 0, WARNING: 2, FAILURE: 0 });
	assert.equal(a.ok, false);

	const passed = analyzeResultLogs("m", {}, "PASSED", [entry("Ok", "SUCCESS")], [], [], "c.json");
	assert.equal(passed.ok, true);
	for (const result of ["UNKNOWN", "RUNNING", ""]) {
		assert.equal(analyzeResultLogs("m", {}, result, [], [], [], "c.json").ok, false, result);
	}
	assert.equal(analyzeResultLogs("m", {}, "REVIEW", [], [], [], "c.json").ok, true);
});

test("expected skips: FAILED counts as skipped; a skip that did not happen fails", () => {
	const skip: ExpectedSkip = { "test-name": "m", variant: "*", "configuration-filename": "c.json" };
	const failed = analyzeResultLogs("m", {}, "FAILED", [entry("X", "FAILURE")], [], [skip], "c.json");
	assert.equal(failed.expected_skip, true);
	assert.equal(failed.unexpected_failures.length, 1); // the failure itself is still unexpected
	assert.equal(failed.ok, false);
	const passed = analyzeResultLogs("m", {}, "PASSED", [], [], [skip], "c.json");
	assert.equal(passed.expected_skip_did_not_happen, true);
	assert.equal(passed.ok, false);
	const otherConfig = analyzeResultLogs("m", {}, "SKIPPED", [], [], [skip], "d.json");
	assert.equal(otherConfig.unexpected_skip, true);
	assert.equal(otherConfig.ok, false);
});

test("unexpected skip and expected skip", () => {
	const skipped = analyzeResultLogs("m", {}, "SKIPPED", [], [], [], "c.json");
	assert.equal(skipped.unexpected_skip, true);
	const expected = analyzeResultLogs(
		"m",
		{},
		"SKIPPED",
		[],
		[],
		[{ "test-name": "m", variant: "*", "configuration-filename": "*" }],
		"c.json",
	);
	assert.equal(expected.ok, true);
});

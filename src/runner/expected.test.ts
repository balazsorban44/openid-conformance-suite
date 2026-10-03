import assert from "node:assert/strict";
import { test } from "node:test";
import type { LogEntry } from "../framework/EventLog.ts";
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

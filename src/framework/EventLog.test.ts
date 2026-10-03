import assert from "node:assert/strict";
import { test } from "node:test";
import { TestInstanceEventLog, type LogEntry } from "./EventLog.ts";

test("log entries carry _id, testId, src, time, seq, then the logged fields (blockId last)", () => {
	const seen: LogEntry[] = [];
	const log = new TestInstanceEventLog("t-ev", (e) => seen.push(e));
	log.log("SRC", "plain message");
	log.log("SRC", { msg: "with fields", result: "INFO", b: 2, a: 1 });

	assert.equal(log.entries.length, 2);
	assert.deepEqual(seen, log.entries, "the sink sees every entry, in order");
	const [first, second] = log.entries;
	assert.deepEqual(Object.keys(first), ["_id", "testId", "src", "time", "seq", "msg"]);
	assert.deepEqual(Object.keys(second), ["_id", "testId", "src", "time", "seq", "msg", "result", "b", "a"]);
	assert.equal(first._id, `t-ev-${first.seq}`);
	assert.equal(second.seq, first.seq + 1, "seq increases by one per entry");
	assert.equal(first.testId, "t-ev");
	assert.equal(first.src, "SRC");
	assert.equal(typeof first.time, "number");
	assert.equal(first["msg"], "plain message");
});

test("blocks: startBlock logs -START-BLOCK- and tags entries until endBlock", async () => {
	const log = new TestInstanceEventLog("t-blk");
	assert.equal(log.startBlock(null).length, 6, "no message: no entry, still a new block id");
	assert.equal(log.entries.length, 0);
	const id = log.startBlock("Block title");
	assert.match(id, /^[0-9a-f]{6}$/);
	log.log("X", { msg: "in block", blockId: "overridden" });
	assert.equal(log.endBlock(), id);
	log.log("X", "after block");

	const [start, inBlock, after] = log.entries;
	assert.deepEqual(Object.keys(start), ["_id", "testId", "src", "time", "seq", "msg", "startBlock", "blockId"]);
	assert.equal(start.src, "-START-BLOCK-");
	assert.equal(start["msg"], "Block title");
	assert.equal(start["startBlock"], true);
	assert.equal(start["blockId"], id);
	assert.deepEqual(Object.keys(inBlock), ["_id", "testId", "src", "time", "seq", "msg", "blockId"]);
	assert.equal(inBlock["blockId"], id);
	assert.equal(after["blockId"], undefined);
	assert.equal(log.endBlock(), null);

	const blockId = await log.runBlock("run", () => log.log("Y", "inside"));
	assert.match(blockId ?? "", /^[0-9a-f]{6}$/);
	assert.equal(log.entries.at(-1)?.["blockId"], blockId);
	assert.equal(log.endBlock(), null, "runBlock ends its block");

	await assert.rejects(
		log.runBlock(null, () => {
			throw new Error("inside block");
		}),
		/inside block/,
	);
	assert.equal(log.endBlock(), null, "runBlock ends its block when the block throws");
});

test("fields named like the entry metadata replace it in place", () => {
	const log = new TestInstanceEventLog("t-meta");
	log.startBlock(null);
	log.log("S", { blockId: "mine", src: "other", msg: "m" });
	const e = log.entries[0];
	assert.deepEqual(Object.keys(e), ["_id", "testId", "src", "time", "seq", "blockId", "msg"]);
	assert.equal(e.src, "other");
	assert.notEqual(e["blockId"], "mine");
});

test("logged values are made JSON-safe", () => {
	const log = new TestInstanceEventLog("t-json");
	const input = { msg: "m", keep: "x" };
	log.log("S", {
		input,
		set: new Set(["a", new Set([1])]),
		map: new Map<string, unknown>([["k", new Set([2])]]),
		error: new Error("boom"),
		headers: new Headers([
			["B", "2"],
			["a", "1"],
		]),
		params: new URLSearchParams("x=1&y=2"),
		big: 5n,
		arr: [new Set([3]), null, { nested: new Error("inner") }],
		json: { toJSON: () => ({ converted: true }) },
		missing: undefined,
		nil: null,
	});
	const e = log.entries[0];
	assert.deepEqual(e["input"], input);
	assert.notEqual(e["input"], input, "objects are copied");
	assert.deepEqual(e["set"], ["a", [1]]);
	assert.deepEqual(e["map"], { k: [2] });
	assert.equal(e["error"], "boom");
	assert.deepEqual(e["headers"], { a: "1", b: "2" });
	assert.equal(e["params"], "x=1&y=2");
	assert.equal(e["big"], 5);
	assert.deepEqual(e["arr"], [[3], null, { nested: "inner" }]);
	assert.deepEqual(e["json"], { converted: true });
	assert.ok("missing" in e, "undefined values keep their key (dropped by JSON.stringify later)");
	assert.equal(e["nil"], null);
});

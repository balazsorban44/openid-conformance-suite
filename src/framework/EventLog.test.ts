import assert from "node:assert/strict";
import { test } from "node:test";
import { AbstractCondition } from "./AbstractCondition.ts";
import { ConditionResult } from "./Condition.ts";
import { Environment } from "./Environment.ts";
import { TestInstanceEventLog, type LogEntry } from "./EventLog.ts";

/*
 * Pins the shape of the entries written to log.json.
 */

test("entry shape: _id, testId, src, time, seq, then the logged map", () => {
	const sunk: LogEntry[] = [];
	const log = new TestInstanceEventLog("abc123", (e) => sunk.push(e));
	const before = Date.now();
	log.log("Src", "a message");
	log.log("Src", { msg: "with map", k: 1, result: "SUCCESS" });
	const [first, second] = log.entries;
	assert.deepEqual(Object.keys(first), ["_id", "testId", "src", "time", "seq", "msg"]);
	assert.deepEqual(Object.keys(second), ["_id", "testId", "src", "time", "seq", "msg", "k", "result"]);
	assert.equal(first._id, `abc123-${first.seq}`);
	assert.equal(second.seq, first.seq + 1); // seq is global across logs, so only relative values are stable
	assert.equal(first.testId, "abc123");
	assert.equal(first.src, "Src");
	assert.ok(first.time >= before && first.time <= Date.now());
	assert.deepEqual(sunk, log.entries);
	assert.equal(sunk[0], log.entries[0]);
});

test("blocks: startBlock entry, blockId on entries inside, endBlock", async () => {
	const log = new TestInstanceEventLog("t");
	log.log("Src", "outside");
	const id = log.startBlock("Block title");
	assert.match(id, /^[0-9a-f]{6}$/);
	log.log("Src", { msg: "inside", blockId: "overridden" });
	assert.equal(log.endBlock(), id);
	assert.equal(log.endBlock(), null);
	log.startBlock(""); // no entry for an empty message, but entries get the new blockId
	log.log("Src", "silent block");
	log.endBlock();
	const ran = log.startBlock("Second");
	log.log("Src", "in second");
	log.endBlock();

	const shapes = log.entries.map(({ _id, testId: _testId, time: _time, seq: _seq, ...rest }) => rest);
	assert.deepEqual(shapes, [
		{ src: "Src", msg: "outside" },
		{ src: "-START-BLOCK-", msg: "Block title", startBlock: true, blockId: id },
		{ src: "Src", msg: "inside", blockId: id },
		{ src: "Src", msg: "silent block", blockId: shapes[3]["blockId"] },
		{ src: "-START-BLOCK-", msg: "Second", startBlock: true, blockId: ran },
		{ src: "Src", msg: "in second", blockId: ran },
	]);
	assert.deepEqual(Object.keys(shapes[1]), ["src", "msg", "startBlock", "blockId"]);
	assert.equal(Object.keys(shapes[2]).at(-1), "blockId");
});

test("values are made JSON-safe", () => {
	const log = new TestInstanceEventLog("t");
	const env = new Environment();
	env.putString("s", "v");
	log.log("Src", {
		set: new Set(["a", new Set([1])]),
		map: new Map<string, unknown>([["k", new Set([2])]]),
		error: new Error("message only"),
		headers: new Headers({ "X-A": "1" }),
		params: new URLSearchParams({ a: "1 2" }),
		big: 10n,
		nested: { arr: [new Set([3])], u: undefined },
		env,
	});
	const { _id, testId: _testId, time: _time, seq: _seq, ...rest } = log.entries[0];
	assert.deepEqual(JSON.parse(JSON.stringify(rest)), {
		src: "Src",
		set: ["a", [1]],
		map: { k: [2] },
		error: "message only",
		headers: { "x-a": "1" },
		params: "a=1+2",
		big: 10,
		nested: { arr: [[3]] },
		env: { store: { _NATIVE_VALUES: { s: "v" } }, keyMap: {} },
	});
	// undefined members stay on the in-memory entry (they disappear in log.json)
	assert.equal("u" in (rest["nested"] as object), true);
});

class Logs extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		this.log("from condition");
		return env;
	}
}

test("requirements appear only when the condition call has some", async () => {
	for (const [reqs, expected] of [
		[[], undefined],
		[["OIDCC-3.1.3.7"], ["OIDCC-3.1.3.7"]],
	] as const) {
		const log = new TestInstanceEventLog("t");
		const c = new Logs();
		c.setProperties("t", log, ConditionResult.FAILURE, [...reqs]);
		await c.execute(new Environment());
		assert.equal("requirements" in log.entries[0], expected !== undefined);
		assert.deepEqual(log.entries[0]["requirements"], expected);
	}
	// the event log itself passes an explicit (even empty) requirements value through
	const log = new TestInstanceEventLog("t");
	log.log("Src", { msg: "skip", requirements: [] });
	assert.deepEqual(log.entries[0]["requirements"], []);
});

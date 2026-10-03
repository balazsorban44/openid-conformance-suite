import assert from "node:assert/strict";
import { test } from "node:test";
import { args, ex, headersFromJson, mapToJsonObject } from "./DataUtils.ts";

test("args", () => {
	assert.equal(JSON.stringify(args("b", 1, "a", "x", "c", null)), '{"b":1,"a":"x","c":null}');
	assert.throws(() => args("a"), { message: "Need an even and nonzero number of arguments" });
});

test("ex() fields and key order", () => {
	assert.deepEqual(ex(null, { a: 1 }), { a: 1 });
	assert.deepEqual(ex(undefined), {});

	const plain = ex(new Error("boom"), { a: 1 });
	assert.deepEqual(Object.keys(plain), ["a", "error", "error_class", "result", "msg", "stacktrace"]);
	assert.equal(plain["error"], "boom");
	assert.equal(plain["error_class"], "Error");
	assert.equal(plain["result"], "FAILURE");
	assert.equal(plain["msg"], "unexpected exception caught: boom");
	assert.ok(Array.isArray(plain["stacktrace"]));

	const withCause = ex(new TypeError("outer", { cause: new RangeError("inner") }), { msg: "given" });
	assert.deepEqual(Object.keys(withCause), [
		"msg",
		"error",
		"error_class",
		"cause",
		"cause_class",
		"cause_stacktrace",
		"result",
	]);
	assert.equal(withCause["msg"], "given");
	assert.equal(withCause["cause"], "inner");
	assert.equal(withCause["cause_class"], "RangeError");

	const nonErrorCause = ex(new Error("outer", { cause: 42 }));
	assert.equal(nonErrorCause["cause"], "42");
	assert.equal("cause_class" in nonErrorCause, false);

	const notAnError = ex("just a string");
	assert.equal(notAnError["error"], "just a string");
	assert.equal(notAnError["error_class"], "Error");
});

test("mapToJsonObject", () => {
	const h = new Headers([
		["X-One", "1"],
		["set-cookie", "a=1"],
		["set-cookie", "b=2"],
		["Accept", "x"],
	]);
	assert.equal(
		JSON.stringify(mapToJsonObject(h, true)),
		JSON.stringify({ accept: "x", "x-one": "1", "set-cookie": ["a=1", "b=2"] }),
	);
	assert.deepEqual(mapToJsonObject({ A: "1", b: ["2", "3"], c: undefined }, false), { A: "1", b: ["2", "3"] });
	assert.deepEqual(mapToJsonObject({ A: "1", a: "2" }, true), { a: ["1", "2"] });
	assert.deepEqual(
		mapToJsonObject(
			[
				["k", "1"],
				["k", "2"],
			],
			false,
		),
		{ k: ["1", "2"] },
	);
});

test("headersFromJson", () => {
	const h = headersFromJson({ Accept: "a", "X-Multi": ["1", "2"], n: 3 });
	assert.deepEqual(
		[...h.entries()],
		[
			["accept", "a"],
			["n", "3"],
			["x-multi", "1, 2"],
		],
	);
	const existing = new Headers({ "x-multi": "0", keep: "k" });
	const out = headersFromJson({ "x-multi": ["1"], keep: "replaced" }, existing);
	assert.equal(out, existing);
	assert.equal(out.get("x-multi"), "1");
	assert.equal(out.get("keep"), "replaced");
	assert.deepEqual([...headersFromJson(null).entries()], []);
	assert.deepEqual([...headersFromJson(undefined).entries()], []);
});

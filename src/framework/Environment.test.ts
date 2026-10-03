import assert from "node:assert/strict";
import { test } from "node:test";
import { Environment, UnexpectedTypeException } from "./Environment.ts";

test("objects, paths and native values", () => {
	const env = new Environment();
	env.putObject("server", { issuer: "https://example.com", nested: { n: 1, b: true } });
	assert.equal(env.getString("server", "issuer"), "https://example.com");
	assert.equal(env.getInteger("server", "nested.n"), 1);
	assert.equal(env.getBoolean("server", "nested.b"), true);
	assert.equal(env.getString("server", "missing"), null);
	assert.equal(env.getElementFromObject("server", "missing"), undefined);
	assert.throws(() => env.getString("server", "nested.n"), UnexpectedTypeException);

	env.putString("state", "abc");
	assert.equal(env.getString("state"), "abc");
	assert.equal(env.getString("nope"), null);
	env.putString("server", "new.path.value", "x");
	assert.equal(env.getString("server", "new.path.value"), "x");
	env.removeElement("server", "new.path.value");
	assert.equal(env.getElementFromObject("server", "new.path.value"), undefined);
	env.removeNativeValue("state");
	assert.equal(env.getString("state"), null);
});

test("key mapping shadows objects", () => {
	const env = new Environment();
	env.putObject("foo", { bar: 1234 });
	env.putObject("baz", { qux: 9876 });
	env.mapKey("foo", "baz");
	assert.deepEqual(env.getObject("foo"), { qux: 9876 });
	assert.deepEqual(env.getObject("baz"), { qux: 9876 });
	assert.equal(env.isKeyMapped("foo"), true);
	assert.equal(env.isKeyShadowed("baz"), true);
	env.unmapKey("foo");
	assert.deepEqual(env.getObject("foo"), { bar: 1234 });
});

test("putObject with null removes", () => {
	const env = new Environment();
	env.putObject("a", { x: 1 });
	env.putObject("a", null);
	assert.equal(env.containsObject("a"), false);
});

test("getElementFromObject: undefined when missing, null for a JSON null", () => {
	const env = new Environment();
	assert.equal(env.getElementFromObject("nope", "a"), undefined);
	env.putObject("o", { a: null, b: { c: null }, arr: [1], s: "x", zero: 0, f: false });
	assert.equal(env.getElementFromObject("o", "a"), null);
	assert.equal(env.getElementFromObject("o", "b.c"), null);
	assert.equal(env.getElementFromObject("o", "b.missing"), undefined);
	assert.equal(env.getElementFromObject("o", "zero"), 0);
	assert.equal(env.getElementFromObject("o", "f"), false);
	assert.equal(env.getElementFromObject("o", "toString"), undefined); // own properties only
	// getters map both to null
	assert.equal(env.getString("o", "a"), null);
	assert.equal(env.getInteger("o", "b.c"), null);
	// traversing through a non-object
	const traverse = (path: string, found: string) =>
		assert.throws(() => env.getElementFromObject("o", path), {
			name: "UnexpectedTypeException",
			message: `An object is required for o.${path} but ${found} was found whilst traversing the path`,
		});
	traverse("a.x", "JsonNull");
	traverse("arr.0", "JsonArray");
	traverse("s.x", "JsonPrimitive");
});

test("type errors of the typed getters and setters", () => {
	const env = new Environment();
	env.putObject("o", { s: "x", n: 1.9, b: true, nested: "leaf" });
	assert.equal(env.getInteger("o", "n"), 1);
	assert.equal(env.getLong("o", "n"), 1);
	const cases: [() => unknown, string][] = [
		[() => env.getString("o", "n"), "If present, a string is expected for o n but JsonPrimitive was found"],
		[() => env.getString("o", "b"), "If present, a string is expected for o b but JsonPrimitive was found"],
		[() => env.getInteger("o", "s"), "A number is required for o s but JsonPrimitive was found"],
		[() => env.getLong("o", "b"), "A number is required for o b but JsonPrimitive was found"],
		[() => env.getBoolean("o", "s"), "A boolean is required for o s but JsonPrimitive was found"],
		[
			() => env.putString("o", "nested.x", "v"),
			"putObject(o, nested.x, obj) found a non-object of type JsonPrimitive in the path at nested",
		],
		[
			() => env.removeElement("o", "s.x"),
			"putObject(o, s.x, obj) found a non-object of type JsonPrimitive in the path at s",
		],
	];
	for (const [fn, message] of cases) {
		assert.throws(fn, (e: unknown) => e instanceof UnexpectedTypeException && e.message === message);
	}
	assert.throws(() => env.removeElement("missing", "a.b"), {
		name: "NoSuchElementException",
		message: "No object with key missing found in path a.b",
	});
	assert.throws(() => env.removeElement("o", "x.y"), { message: "No object with key o found in path x.y" });
});

test("mapKey/unmapKey: shadowing, no chaining, writes go to the target", () => {
	const env = new Environment();
	assert.equal(env.mapKey("a", "b"), null);
	assert.equal(env.mapKey("a", "c"), "b");
	assert.equal(env.getEffectiveKey("a"), "c");
	assert.equal(env.isKeyShadowed("c"), true);
	assert.equal(env.isKeyShadowed("b"), false);
	assert.equal(env.isKeyMapped("c"), false);
	env.putObject("a", { via: "a" }); // stored under "c"
	assert.deepEqual(env.getObject("c"), { via: "a" });
	assert.equal(env.containsObject("a"), true);
	env.mapKey("c", "d"); // not followed when reading "a"
	assert.deepEqual(env.getObject("a"), { via: "a" });
	assert.equal(env.getObject("c"), null);
	env.putString("a", "path.x", "v"); // putElement on a mapped key
	assert.equal(env.getString("c", "path.x"), null);
	assert.equal(env.getString("a", "path.x"), "v");
	env.removeObject("a");
	assert.equal(env.getEffectiveKey("a"), "c");
	assert.equal(env.unmapKey("a"), "c");
	assert.equal(env.unmapKey("a"), null);
	assert.equal(env.getEffectiveKey("a"), "a");
});

test("native values: separate from objects, never mapped", async () => {
	const env = new Environment();
	env.putString("k", "string");
	env.putObject("k", { o: 1 });
	env.mapKey("k", "other");
	assert.equal(env.getString("k"), "string");
	env.putInteger("i", 5);
	env.putLong("l", 2 ** 40);
	env.putBoolean("b", false);
	assert.equal(env.getInteger("i"), 5);
	assert.equal(env.getLong("l"), 2 ** 40);
	assert.equal(env.getBoolean("b"), false);
	assert.throws(() => env.getString("i"), {
		message: "If present, a string is expected for _NATIVE_VALUES i but JsonPrimitive was found",
	});
	env.putString("k", null);
	assert.equal(env.getString("k"), null);
	env.removeNativeValue("i");
	assert.equal(env.getInteger("i"), null);
	assert.equal(env.isKeyMapped("x"), false);
	assert.deepEqual(env.toJSON().keyMap, { k: "other" });
	assert.equal(env.nextSystemCounter("c"), 0);
	assert.equal(env.nextSystemCounter("c"), 1);
});

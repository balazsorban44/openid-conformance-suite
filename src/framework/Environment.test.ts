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

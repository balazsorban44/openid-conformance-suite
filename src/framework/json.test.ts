import assert from "node:assert/strict";
import { test } from "node:test";
import {
	JsonParseException,
	OIDFJSON,
	UnexpectedJsonTypeException,
	ValueIsJsonNullException,
	deepCopy,
	has,
	jsonArrayContains,
	jsonEquals,
	parseJson,
	parseJsonObject,
} from "./json.ts";

// Pins the OIDFJSON accessors and their exact type-error messages.

function throwsType(fn: () => unknown, message: string): void {
	assert.throws(fn, (e: unknown) => {
		assert.ok(e instanceof UnexpectedJsonTypeException);
		assert.equal(e.name, "UnexpectedJsonTypeException");
		assert.equal(e.message, message);
		return true;
	});
}

test("OIDFJSON number accessors", () => {
	assert.equal(OIDFJSON.getNumber(1.5), 1.5);
	assert.equal(OIDFJSON.getInt(1.9), 1);
	assert.equal(OIDFJSON.getInt(-1.9), -1);
	assert.equal(OIDFJSON.getLong(2.5), 2);
	assert.equal(OIDFJSON.getDouble(2.5), 2.5);
	throwsType(() => OIDFJSON.getNumber("1"), 'getNumber called on something that is not a number: "1"');
	throwsType(() => OIDFJSON.getInt(null), "getInt called on something that is not a number: null");
	throwsType(() => OIDFJSON.getLong(true), "getLong called on something that is not a number: true");
	throwsType(() => OIDFJSON.getDouble({ a: 1 }), 'getDouble called on something that is not a number: {"a":1}');
	throwsType(() => OIDFJSON.getNumber(undefined), "getNumber called on something that is not a number: undefined");
});

test("OIDFJSON string and boolean accessors", () => {
	assert.equal(OIDFJSON.getString("s"), "s");
	throwsType(() => OIDFJSON.getString(1), "getString called on something that is not a string: 1");
	throwsType(() => OIDFJSON.getString(["a"]), 'getString called on something that is not a string: ["a"]');
	assert.equal(OIDFJSON.getStringOrNull(null), null);
	assert.equal(OIDFJSON.getStringOrNull(undefined), null);
	assert.equal(OIDFJSON.getStringOrNull("s"), "s");
	throwsType(() => OIDFJSON.getStringOrNull(1), "getString called on something that is not a string: 1");
	assert.equal(OIDFJSON.tryGetString(undefined), null);
	assert.equal(OIDFJSON.tryGetString("s"), "s");
	throwsType(() => OIDFJSON.tryGetString(false), "getString called on something that is not a string: false");
	assert.equal(OIDFJSON.isString("s"), true);
	assert.equal(OIDFJSON.isString(1), false);
	assert.equal(OIDFJSON.isString(null), false);
	assert.equal(OIDFJSON.getBoolean(false), false);
	throwsType(() => OIDFJSON.getBoolean("true"), 'getBoolean called on something that is not a boolean: "true"');
});

test("OIDFJSON conversions", () => {
	assert.equal(OIDFJSON.forceConversionToString("s"), "s");
	assert.equal(OIDFJSON.forceConversionToString(12), "12");
	throwsType(
		() => OIDFJSON.forceConversionToString(true),
		"forceConversionToString called on something that is neither a number nor a string: true",
	);
	assert.equal(OIDFJSON.forceConversionToNumber(3), 3);
	assert.equal(OIDFJSON.forceConversionToNumber("3.5"), 3.5);
	assert.throws(
		() => OIDFJSON.forceConversionToNumber(null),
		(e: unknown) => e instanceof ValueIsJsonNullException && e.message === "Element has a JsonNull value",
	);
	throwsType(
		() => OIDFJSON.forceConversionToNumber("abc"),
		"forceConversionToNumber called on a string that is not a number: abc",
	);
	throwsType(
		() => OIDFJSON.forceConversionToNumber(" "),
		"forceConversionToNumber called on a string that is not a number:  ",
	);
	throwsType(
		() => OIDFJSON.forceConversionToNumber([1]),
		"forceConversionToNumber called on something that is neither a number nor a string: [1]",
	);
	const map = { a: 1, b: undefined, c: [new Map()] };
	assert.deepEqual(OIDFJSON.convertMapToJsonObject(map), { a: 1, c: [{}] });
	assert.deepEqual(Object.keys(OIDFJSON).sort(), [
		"convertMapToJsonObject",
		"forceConversionToNumber",
		"forceConversionToString",
		"getBoolean",
		"getDouble",
		"getInt",
		"getLong",
		"getNumber",
		"getString",
		"getStringOrNull",
		"isString",
		"tryGetString",
	]);
});

test("json helpers", () => {
	assert.deepEqual(parseJson('{"a":[1]}'), { a: [1] });
	assert.throws(() => parseJson("{"), JsonParseException);
	assert.throws(() => parseJsonObject("[]"), { name: "UnexpectedJsonTypeException", message: "Not a JSON Object: []" });
	assert.equal(has({ a: undefined as never }, "a"), true);
	assert.equal(has(null, "a"), false);
	assert.equal(has({}, "toString"), false);
	assert.equal(jsonEquals({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] }), true);
	assert.equal(jsonEquals({ a: 1 }, { a: 1, b: 2 }), false);
	assert.equal(jsonArrayContains(["x", 1], "x"), true);
	assert.equal(jsonArrayContains(null, "x"), false);
	const o = { a: { b: 1 } };
	const copy = deepCopy(o);
	assert.deepEqual(copy, o);
	assert.notEqual(copy.a, o.a);
	assert.equal(deepCopy(undefined), undefined);
});

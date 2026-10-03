import assert from "node:assert/strict";
import { test } from "vitest";
import { IllegalArgumentException, isBlank, javaBase64Decode, toUsAscii, urlEncode } from "./strings.ts";

// Expected values were produced with OpenJDK 21.

test("toUsAscii: String.getBytes(US_ASCII)", () => {
	assert.equal(toUsAscii("abc-._~"), "abc-._~");
	assert.equal(toUsAscii("aé€"), "a??");
	// a surrogate pair is one code point, so one '?'
	assert.equal(toUsAscii("x😀y"), "x?y");
	// a lone surrogate is unmappable too
	assert.equal(toUsAscii("x\uD83Dy"), "x?y");
	assert.equal(toUsAscii("\u007f\u0080"), "\u007f?");
});

test("isBlank: String.isBlank()", () => {
	assert.equal(isBlank(""), true);
	assert.equal(isBlank(" "), true);
	assert.equal(isBlank("\t\n"), true);
	assert.equal(isBlank("　"), true);
	// non-breaking spaces are not Character.isWhitespace
	assert.equal(isBlank(" "), false);
	assert.equal(isBlank(" "), false);
	assert.equal(isBlank(" a "), false);
});

test("urlEncode: URLEncoder.encode(s, UTF_8)", () => {
	assert.equal(urlEncode("a b+c*~-._!'()/:é@"), "a+b%2Bc*%7E-._%21%27%28%29%2F%3A%C3%A9%40");
});

test("javaBase64Decode: Base64.getDecoder().decode()", () => {
	assert.equal(javaBase64Decode("QUJD").toString(), "ABC");
	assert.equal(javaBase64Decode("QUI=").toString(), "AB");
	// padding is optional
	assert.equal(javaBase64Decode("QUI").toString(), "AB");
	assert.equal(javaBase64Decode("QQ").toString(), "A");

	const failures: [string, string][] = [
		["QU*D", "Illegal base64 character 2a"],
		["QUJD\n", "Illegal base64 character a"],
		["QUJD=", "Input byte array has wrong 4-byte ending unit"],
		["QQ=", "Input byte array has wrong 4-byte ending unit"],
		["QUJDQ", "Last unit does not have enough valid bits"],
	];
	for (const [input, message] of failures) {
		assert.throws(
			() => javaBase64Decode(input),
			(e: unknown) => e instanceof IllegalArgumentException && e.message === message,
			JSON.stringify(input),
		);
	}
});

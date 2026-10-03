import assert from "node:assert/strict";
import { test } from "node:test";
import { JavaHashMap } from "./HashMap.ts";

// Expected orders are what `new HashMap<>()` + put + keySet() prints on JDK 21.0.11.
const order = (keys: string[]) =>
	JavaHashMap.of(keys.map((k) => [k, 1]))
		.entries()
		.map(([k]) => k);

test("JavaHashMap: JWS header member order", () => {
	assert.deepEqual(order(["alg", "typ", "kid"]), ["kid", "typ", "alg"]);
});

test("JavaHashMap: JWK member order", () => {
	assert.deepEqual(order(["kty", "use", "alg", "kid", "n", "e", "d", "p", "q", "dp", "dq", "qi"]), [
		"p",
		"kty",
		"q",
		"d",
		"e",
		"use",
		"kid",
		"qi",
		"dp",
		"alg",
		"dq",
		"n",
	]);
	assert.deepEqual(order(["kty", "crv", "x", "y", "d", "use", "kid", "alg"]), [
		"kty",
		"d",
		"crv",
		"use",
		"kid",
		"x",
		"y",
		"alg",
	]);
});

test("JavaHashMap: claims member order", () => {
	assert.deepEqual(order(["iss", "sub", "aud", "exp", "iat", "nonce"]), ["sub", "aud", "iss", "exp", "iat", "nonce"]);
});

test("JavaHashMap: order after a resize (13 entries > threshold 12)", () => {
	const keys = Array.from({ length: 13 }, (_, i) => "k" + i);
	assert.deepEqual(order(keys), ["k0", "k1", "k2", "k3", "k4", "k5", "k11", "k6", "k10", "k7", "k8", "k12", "k9"]);
});

test("JavaHashMap: put replaces the value in place, putAll pre-sizes, toJsonObject keeps the order", () => {
	const m = JavaHashMap.of([
		["alg", "RS256"],
		["typ", "JWT"],
	]);
	m.put("alg", "PS256");
	m.put("kid", "k1");
	assert.equal(JSON.stringify(m.toJsonObject()), '{"kid":"k1","typ":"JWT","alg":"PS256"}');

	const n = new JavaHashMap();
	n.putAll(Array.from({ length: 13 }, (_, i): [string, number] => ["k" + i, i]));
	assert.equal(n.entries().length, 13);
	assert.deepEqual(
		n.entries().map(([k]) => k),
		order(Array.from({ length: 13 }, (_, i) => "k" + i)),
	);
});

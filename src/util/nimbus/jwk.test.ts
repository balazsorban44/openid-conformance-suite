import assert from "node:assert/strict";
import { test } from "node:test";
import { errors } from "jose";
import { isJOSEException, JOSEException, KeyLengthException, ParseException } from "./errors.ts";
import { getRequiredParams, isPrivate, parseJWK, parseJWKSet, toPublicJWK } from "./jwk.ts";

const EC = {
	kty: "EC",
	crv: "P-256",
	x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
	y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	d: "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
};

function parseError(f: () => unknown): string {
	try {
		f();
	} catch (e) {
		assert.ok(e instanceof ParseException, `expected a ParseException, got ${String(e)}`);
		return e.message;
	}
	assert.fail("expected a ParseException");
}

test("parseJWK: Nimbus toJSONObject() members and order; unknown members dropped", () => {
	const jwk = parseJWK({ ...EC, use: "sig", kid: "k1", alg: "ES256", foo: "bar" });
	// as nimbus-jose-jwt 10.9 prints JWK.parse(json).toJSONObject().keySet()
	assert.equal(Object.keys(jwk).join(), "kty,d,use,crv,kid,x,y,alg");
	assert.equal(jwk["foo"], undefined);
	assert.equal(parseJWK(JSON.stringify(EC))["crv"], "P-256");
});

test("parseJWK / parseJWKSet: error messages", () => {
	assert.equal(
		parseError(() => parseJWK({ crv: "P-256" })),
		'Missing key type "kty" parameter',
	);
	assert.equal(
		parseError(() => parseJWK({ kty: "RSA", e: "AQAB" })),
		"The modulus value must not be null",
	);
	assert.equal(
		parseError(() => parseJWK({ ...EC, crv: "P-384" })),
		"Invalid EC JWK: The 'x' and 'y' public coordinates are not on the P-384 curve",
	);
	assert.equal(
		parseError(() => parseJWK({ ...EC, key_ops: ["sign"], use: "enc" })),
		'The key use "use" and key options "key_ops" parameters are not consistent, see RFC 7517, section 4.3',
	);
	assert.equal(
		parseError(() => parseJWKSet("{}")),
		'Missing required "keys" member',
	);
	assert.equal(
		parseError(() => parseJWKSet('{"keys":[1]}')),
		'The "keys" JSON array must contain JSON objects only',
	);
	assert.equal(
		parseError(() => parseJWKSet({ keys: [EC, { kty: "RSA" }] })),
		"Invalid JWK at position 1: The modulus value must not be null",
	);
	assert.equal(
		parseError(() => parseJWKSet('{"keys":[],"keys":[]}')),
		"Invalid JSON object",
	);
});

test("parseJWKSet: unknown key types are dropped, custom members kept (HashMap order)", () => {
	const set = parseJWKSet({ keys: [{ kty: "foo" }, EC], custom: 1 });
	assert.equal(set.keys.length, 1);
	assert.equal(Object.keys(set).join(), "keys,custom");
});

test("toPublicJWK / isPrivate / getRequiredParams", () => {
	assert.equal(isPrivate(EC), true);
	const pub = toPublicJWK(EC);
	assert.equal(JSON.stringify(pub), JSON.stringify({ kty: "EC", crv: "P-256", x: EC.x, y: EC.y }));
	assert.equal(isPrivate(pub as object as typeof EC), false);
	assert.equal(toPublicJWK({ kty: "oct", k: "AAAA" }), null);
	assert.equal(isPrivate({ kty: "oct", k: "AAAA" }), true);
	assert.equal(
		JSON.stringify(getRequiredParams({ ...EC, kid: "k" })),
		JSON.stringify({ crv: "P-256", kty: "EC", x: EC.x, y: EC.y }),
	);
	assert.deepEqual(Object.keys(getRequiredParams({ kty: "RSA", n: "n", e: "e", d: "d" })), ["e", "kty", "n"]);
});

test("isJOSEException: the JOSEException port and jose's errors, not TypeError", () => {
	assert.equal(isJOSEException(new JOSEException("x")), true);
	assert.equal(isJOSEException(new KeyLengthException("x")), true);
	assert.equal(isJOSEException(new errors.JWSInvalid("x")), true);
	assert.equal(isJOSEException(new TypeError("x")), false);
	assert.equal(isJOSEException(new ParseException("x")), false);
	assert.equal(isJOSEException("x"), false);
});

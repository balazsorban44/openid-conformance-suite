import assert from "node:assert/strict";
import { test } from "vitest";
import { ParseException } from "./errors.ts";
import { parseClaimsSet, parseJWEObject, jwtParserParse, parseSignedJWT } from "./jose-jwt.ts";

const b64 = (s: string | object) => Buffer.from(typeof s === "string" ? s : JSON.stringify(s)).toString("base64url");
const VALID = b64({ alg: "RS256", kid: "r1" }) + "." + b64({ sub: "x" }) + ".c2ln";

function parseError(f: () => unknown): string {
	try {
		f();
	} catch (e) {
		assert.ok(e instanceof ParseException, `expected a ParseException, got ${String(e)}`);
		return e.message;
	}
	assert.fail("expected a ParseException");
}

test("parseSignedJWT: a valid JWS", () => {
	const jwt = parseSignedJWT(VALID);
	assert.equal(jwt.type, "signed");
	assert.equal(jwt.serialized, VALID);
	assert.deepEqual(jwt.parts, VALID.split("."));
	// Nimbus' JWSHeader.toJSONObject() order (a HashMap): kid before alg
	assert.equal(JSON.stringify(jwt.header), '{"kid":"r1","alg":"RS256"}');
	assert.equal(jwt.payload, '{"sub":"x"}');
	assert.equal(jwt.signature, "c2ln");
});

// Every message below is what nimbus-jose-jwt 10.9 SignedJWT.parse throws for the same input.
test("parseSignedJWT: error messages", () => {
	const cases: [string, string][] = [
		[b64({ alg: "RSA-OAEP", enc: "A128GCM" }) + ".a.b.c.d", "Unexpected number of Base64URL parts, must be three"],
		[b64({ alg: "none" }) + "." + b64({ a: 1 }) + ".", "Invalid JWS header: Not a JWS header"],
		[b64({ alg: "none" }) + "." + b64({ a: 1 }) + ".abc", "Invalid JWS header: Not a JWS header"],
		[b64({ alg: "RSA-OAEP", enc: "A128GCM" }) + ".a.b", "Invalid JWS header: Not a JWS header"],
		["abc", "Invalid serialized unsecured/JWS/JWE object: Missing part delimiters"],
		["a.b", "Invalid serialized unsecured/JWS/JWE object: Missing second delimiter"],
		["a.b.c.d.e.f", "Invalid serialized unsecured/JWS/JWE object: Too many part delimiters"],
		[b64("hello") + ".e30.sig", "Invalid JWS header: Invalid JSON object"],
		[b64({ alg: "RS256" }) + ".e30.", "The signature must not be empty"],
		[b64({ alg: "RS256", kid: 5 }) + ".e30.sig", "Invalid JWS header: Unexpected type of JSON object member kid"],
		[b64({ typ: "JWT" }) + ".e30.sig", 'Invalid JWS header: Missing "alg" in header JSON object'],
	];
	for (const [token, message] of cases) {
		assert.equal(
			parseError(() => parseSignedJWT(token)),
			message,
			token,
		);
	}
});

test("parseSignedJWT: no character check (Nimbus trims and ignores non-base64url characters)", () => {
	assert.equal(parseSignedJWT("  " + VALID + "\n").header["alg"], "RS256");
	assert.equal(parseSignedJWT(VALID.slice(0, 10) + "*" + VALID.slice(10)).header["kid"], "r1");
});

test("jwtParserParse (JWTParser.parse) dispatches on the header", () => {
	assert.equal(jwtParserParse(VALID).type, "signed");
	assert.equal(jwtParserParse(b64({ alg: "none" }) + "." + b64({ a: 1 }) + ".").type, "plain");
	assert.equal(jwtParserParse(b64({ alg: "RSA-OAEP", enc: "A128GCM" }) + ".a.b.c.d").type, "encrypted");
	assert.equal(
		parseError(() => jwtParserParse("abc")),
		"Invalid JWT serialization: Missing dot delimiter(s)",
	);
	assert.equal(
		parseError(() => jwtParserParse(b64({ alg: "none" }) + "." + b64({ a: 1 }) + ".abc")),
		"Unexpected third Base64URL part in the unsecured JWT object",
	);
	assert.equal(
		parseError(() => jwtParserParse("a.b")),
		"Invalid unsecured/JWS/JWE header: Invalid JSON object",
	);
});

test("parseJWEObject (JWEObject.parse)", () => {
	const jwe = parseJWEObject(b64({ enc: "A128GCM", alg: "RSA-OAEP", kid: "e1" }) + ".a.b.c.d");
	assert.equal(jwe.type, "encrypted");
	assert.equal(JSON.stringify(jwe.header), '{"kid":"e1","enc":"A128GCM","alg":"RSA-OAEP"}');
	assert.equal(
		parseError(() => parseJWEObject(VALID)),
		"Unexpected number of Base64URL parts, must be five",
	);
});

test("parseClaimsSet: Nimbus JWTClaimsSet rendering", () => {
	const claims = { iss: "i", sub: 5, aud: ["a"], exp: 1700000000.9, iat: 1700000000, nbf: null, jti: "j", nonce: "n" };
	// single audience as a string, numeric sub as a string, dates truncated, null claims dropped, HashMap order
	assert.equal(
		JSON.stringify(parseClaimsSet(claims)),
		'{"sub":"5","aud":"a","iss":"i","exp":1700000000,"iat":1700000000,"nonce":"n","jti":"j"}',
	);
	// includeNullValues keeps them (toJSONObject(true))
	assert.equal(parseClaimsSet(claims, true)["nbf"], null);
	assert.deepEqual(parseClaimsSet({ aud: ["a", "b"] }), { aud: ["a", "b"] });
	assert.deepEqual(parseClaimsSet({ aud: "a" }), { aud: "a" });
	assert.deepEqual(parseClaimsSet({ aud: [] }), {});
});

test("parseClaimsSet: error messages", () => {
	assert.equal(
		parseError(() => parseClaimsSet({ iss: 5 })),
		"Unexpected type of JSON object member iss",
	);
	assert.equal(
		parseError(() => parseClaimsSet({ sub: {} })),
		"Illegal sub claim",
	);
	assert.equal(
		parseError(() => parseClaimsSet({ aud: 5 })),
		"Illegal aud claim",
	);
	assert.equal(
		parseError(() => parseClaimsSet({ aud: [1] })),
		"JSON object member aud is not an array of strings",
	);
	assert.equal(
		parseError(() => parseClaimsSet({ exp: "soon" })),
		"Unexpected type of JSON object member exp",
	);
});

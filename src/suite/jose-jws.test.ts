import assert from "node:assert/strict";
import { createHash, createPrivateKey, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "vitest";
import { CompactSign, exportJWK, generateKeyPair, importJWK } from "jose";
import type { JsonObject } from "./json.ts";
import { JOSEException, KeyLengthException } from "./errors.ts";
import { parseJWKSet, toPublicJWK, type JWK } from "./jose-jwk.ts";
import {
	selectJWSJwks,
	unsupportedJWSAlgorithm,
	verifySignedJWT,
	createJWSSigner,
	ecSigner,
	macSigner,
	ed25519Signer,
} from "./jose-jws.ts";
import { parseSignedJWT } from "./jose-jwt.ts";

async function generate(alg: string, options: Record<string, unknown> = {}): Promise<JsonObject> {
	const { privateKey } = await generateKeyPair(alg, { extractable: true, ...options });
	return (await exportJWK(privateKey)) as JsonObject;
}

const rsa = await generate("RS256");
const ec256 = await generate("ES256");
const ec384 = await generate("ES384");
const ed25519 = await generate("EdDSA", { crv: "Ed25519" });
const secret = Buffer.alloc(32, 7).toString("base64url");
const certPem = readFileSync(new URL("../../configs/certs/localhost.crt", import.meta.url));
const cert = new X509Certificate(certPem);
const certKey = createPrivateKey(readFileSync(new URL("../../configs/certs/localhost.key", import.meta.url)));
const certThumbprint = createHash("sha256").update(cert.raw).digest("base64url");

const jwks = parseJWKSet({
	keys: [
		{ ...rsa, kid: "r-sig", use: "sig" },
		{ ...rsa, kid: "r-ps", alg: "PS256" },
		{ ...rsa, kid: "r-enc", use: "enc" },
		{ ...(certKey.export({ format: "jwk" }) as JsonObject), kid: "r-x5c", x5c: [cert.raw.toString("base64")] },
		{ ...toPublicJWK(rsa), kid: "r-x5t", "x5t#S256": certThumbprint },
		{ ...ec256, kid: "e256" },
		{ ...ec384, kid: "e384", alg: "ES384" },
		{ ...ed25519, kid: "d25519" },
		{ kty: "OKP", crv: "Ed448", x: Buffer.alloc(57, 1).toString("base64url"), kid: "d448" },
		{ kty: "oct", k: secret, kid: "o1" },
		{ kty: "oct", k: secret, kid: "o384", alg: "HS384" },
	],
});

/** kid of each selected key, with "*" for a key with private/secret material */
const selected = (header: JsonObject) =>
	selectJWSJwks(header, jwks).map((k) => String(k["kid"]) + ("d" in k || k["kty"] === "oct" ? "*" : ""));

test("selectJWSJwks: alg only - every key of the type with use sig/absent and alg equal/absent", () => {
	// asymmetric keys come as their public JWK, followed by the private JWK itself
	assert.deepEqual(selected({ alg: "RS256" }), ["r-sig", "r-sig*", "r-x5c", "r-x5c*", "r-x5t"]);
	assert.deepEqual(selected({ alg: "PS256" }), ["r-sig", "r-sig*", "r-ps", "r-ps*", "r-x5c", "r-x5c*", "r-x5t"]);
	assert.deepEqual(selected({ alg: "ES256" }), ["e256", "e256*"]);
	assert.deepEqual(selected({ alg: "ES384" }), ["e256", "e256*", "e384", "e384*"]);
	// secret keys as is, no use restriction
	assert.deepEqual(selected({ alg: "HS256" }), ["o1*"]);
	assert.deepEqual(selected({ alg: "HS384" }), ["o1*", "o384*"]);
});

test("selectJWSJwks: by kid", () => {
	assert.deepEqual(selected({ alg: "RS256", kid: "r-sig" }), ["r-sig", "r-sig*"]);
	assert.deepEqual(selected({ alg: "RS256", kid: "r-enc" }), []);
	assert.deepEqual(selected({ alg: "RS256", kid: "nope" }), []);
	assert.deepEqual(selected({ alg: "HS384", kid: "o384" }), ["o384*"]);
});

test("selectJWSJwks: by x5t#S256 - the key's own x5t#S256 or the thumbprint of its first x5c certificate", () => {
	assert.deepEqual(selected({ alg: "RS256", "x5t#S256": certThumbprint }), ["r-x5c", "r-x5c*", "r-x5t"]);
	assert.deepEqual(selected({ alg: "RS256", "x5t#S256": "no-match" }), []);
	assert.deepEqual(selected({ alg: "RS256", kid: "r-x5t", "x5t#S256": certThumbprint }), ["r-x5t"]);
});

test("selectJWSJwks: EdDSA restricts the curves, Ed25519/Ed448 do not (Nimbus 10.9)", () => {
	assert.deepEqual(selected({ alg: "EdDSA" }), ["d25519", "d25519*", "d448"]);
	assert.deepEqual(selected({ alg: "Ed25519" }), ["d25519", "d25519*", "d448"]);
	assert.deepEqual(selected({ alg: "Ed448" }), ["d25519", "d25519*", "d448"]);
});

test("selectJWSJwks: unsupported algorithms select nothing", () => {
	for (const alg of ["dir", "A128KW", "RSA-OAEP", "none", "ML-DSA-44"]) {
		assert.deepEqual(selected({ alg }), [], alg);
	}
});

test("unsupportedJWSAlgorithm (AlgorithmSupportMessage)", () => {
	assert.equal(unsupportedJWSAlgorithm("ES384", ["ES256"]), "Unsupported JWS algorithm ES384, must be ES256");
	assert.equal(
		unsupportedJWSAlgorithm("RS256", ["HS256", "HS384", "HS512"]),
		"Unsupported JWS algorithm RS256, must be HS256, HS384 or HS512",
	);
});

async function sign(jwk: JsonObject, header: JsonObject): Promise<string> {
	const key = await importJWK(jwk as JWK, header["alg"] as string);
	return new CompactSign(Buffer.from('{"sub":"x"}')).setProtectedHeader(header as { alg: string }).sign(key);
}

async function rejection(p: Promise<unknown>): Promise<Error> {
	try {
		await p;
	} catch (e) {
		return e as Error;
	}
	assert.fail("expected a rejection");
}

test("verifySignedJWT: verifies, or returns false for a signature mismatch", async () => {
	const pub = toPublicJWK(rsa) as JWK;
	const jwt = parseSignedJWT(await sign(rsa, { alg: "RS256" }));
	assert.equal(await verifySignedJWT(jwt, { jwk: pub, key: await importJWK(pub, "RS256") }), true);
	const other = toPublicJWK(await generate("RS256")) as JWK;
	assert.equal(await verifySignedJWT(jwt, { jwk: other, key: await importJWK(other, "RS256") }), false);
	const hs = parseSignedJWT(await sign({ kty: "oct", k: secret }, { alg: "HS256" }));
	assert.equal(await verifySignedJWT(hs, { jwk: { kty: "oct" }, key: Buffer.from(secret, "base64url") }), true);
	assert.equal(await verifySignedJWT(hs, { jwk: { kty: "oct" }, key: Buffer.alloc(32, 8) }), false);
});

test("verifySignedJWT: the Nimbus verifier checks", async () => {
	const ecPub = toPublicJWK(ec256) as JWK;
	const es256 = parseSignedJWT(await sign(ec256, { alg: "ES256" }));
	const onP384 = await rejection(
		verifySignedJWT(es256, { jwk: { kty: "EC", crv: "P-384" }, key: await importJWK(ecPub, "ES256") }),
	);
	assert.ok(onP384 instanceof JOSEException);
	assert.equal(onP384.message, "Unsupported JWS algorithm ES256, must be ES384");

	const edPub = toPublicJWK(ed25519) as JWK;
	const ed448Header = parseSignedJWT(b64({ alg: "Ed448" }) + ".e30.c2ln");
	const ed = await rejection(verifySignedJWT(ed448Header, { jwk: edPub, key: await importJWK(edPub, "EdDSA") }));
	assert.equal(ed.message, "Ed25519Verifier requires alg=Ed25519 or alg=EdDSA in JWSHeader");

	// MACVerifier: secret length for the algorithm (KeyLengthException), then the algorithm itself
	const hs384 = parseSignedJWT(b64({ alg: "HS384" }) + ".e30.c2ln");
	const short = await rejection(verifySignedJWT(hs384, { jwk: { kty: "oct" }, key: Buffer.alloc(32, 7) }));
	assert.ok(short instanceof KeyLengthException);
	assert.equal(short.message, "The secret length for HS384 must be at least 384 bits");
	const rs256 = parseSignedJWT(b64({ alg: "RS256" }) + ".e30.c2ln");
	const notMac = await rejection(verifySignedJWT(rs256, { jwk: { kty: "oct" }, key: Buffer.alloc(32, 7) }));
	assert.equal(notMac.message, "Unsupported JWS algorithm RS256, must be HS256, HS384 or HS512");
});

test("verifySignedJWT: unprocessed critical header parameters do not verify", async () => {
	const pub = toPublicJWK(rsa) as JWK;
	const jwt = parseSignedJWT(b64({ alg: "RS256", crit: ["foo"], foo: 1 }) + ".e30.c2ln");
	assert.equal(await verifySignedJWT(jwt, { jwk: pub, key: await importJWK(pub, "RS256") }), false);
});

test("JWSSigner: signs, and fails like the Nimbus signers / DefaultJWSSignerFactory", async () => {
	const jws = await createJWSSigner(rsa as JWK, "RS256").sign({ alg: "RS256", kid: "k" }, '{"a":1}');
	assert.equal(parseSignedJWT(jws).header["kid"], "k");
	assert.equal(
		ecSigner(ec384 as JWK)
			.supportedJWSAlgorithms()
			.join(),
		"ES384",
	);
	assert.equal(
		macSigner({ kty: "oct", k: Buffer.alloc(48).toString("base64url") })
			.supportedJWSAlgorithms()
			.join(),
		"HS256,HS384",
	);

	const failures: [() => unknown, string][] = [
		[
			() => createJWSSigner(rsa as JWK, "ES256"),
			"Invalid JWK: Must be an instance of class com.nimbusds.jose.jwk.ECKey",
		],
		[() => createJWSSigner(toPublicJWK(rsa) as JWK, "RS256"), "Expected private JWK but none available"],
		[
			() => createJWSSigner({ ...rsa, use: "enc" } as JWK, "RS256"),
			"The JWK use must be sig (signature) or unspecified",
		],
		[() => createJWSSigner(rsa as JWK, "dir"), "Unsupported JWS algorithm: dir"],
		[
			() => macSigner({ kty: "oct", k: Buffer.alloc(16).toString("base64url") }),
			"The secret length must be at least 256 bits",
		],
		[
			() => ed25519Signer({ ...ec256, kty: "OKP", crv: "Ed448" } as JWK),
			"Ed25519Signer only supports OctetKeyPairs with crv=Ed25519",
		],
	];
	for (const [f, message] of failures) {
		assert.throws(f, (e: unknown) => e instanceof JOSEException && e.message === message, message);
	}
	const unsupported = await rejection(createJWSSigner(ec256 as JWK, "ES256").sign({ alg: "ES384" }, "{}"));
	assert.equal(
		unsupported.message,
		"The ES384 algorithm is not allowed or supported by the JWS signer: Supported algorithms: [ES256]",
	);
});

function b64(o: object): string {
	return Buffer.from(JSON.stringify(o)).toString("base64url");
}

import assert from "node:assert/strict";
import { test } from "vitest";
import { curvesForJWSAlgorithm, EC_CURVE_ALGORITHM, keyTypeForAlgorithm, requireAlgorithmName } from "./algorithms.ts";

// Expected values checked against nimbus-jose-jwt 10.9 (KeyType.forAlgorithm, Curve.forJWSAlgorithm).

test("keyTypeForAlgorithm: JWS algorithms", () => {
	for (const alg of ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]) {
		assert.equal(keyTypeForAlgorithm(alg), "RSA", alg);
	}
	for (const alg of ["ES256", "ES256K", "ES384", "ES512"]) {
		assert.equal(keyTypeForAlgorithm(alg), "EC", alg);
	}
	for (const alg of ["EdDSA", "Ed25519", "Ed448"]) {
		assert.equal(keyTypeForAlgorithm(alg), "OKP", alg);
	}
	for (const alg of ["HS256", "HS384", "HS512"]) {
		assert.equal(keyTypeForAlgorithm(alg), "oct", alg);
	}
});

test("keyTypeForAlgorithm: JWE algorithms, unknown names and null", () => {
	assert.equal(keyTypeForAlgorithm("RSA-OAEP-256"), "RSA");
	assert.equal(keyTypeForAlgorithm("RSA1_5"), "RSA");
	assert.equal(keyTypeForAlgorithm("ECDH-ES+A128KW"), "EC");
	assert.equal(keyTypeForAlgorithm("dir"), "oct");
	assert.equal(keyTypeForAlgorithm("A128KW"), "oct");
	assert.equal(keyTypeForAlgorithm("A256GCMKW"), "oct");
	assert.equal(keyTypeForAlgorithm("PBES2-HS256+A128KW"), "oct");
	assert.equal(keyTypeForAlgorithm("none"), null);
	assert.equal(keyTypeForAlgorithm("ML-DSA-44"), null);
	assert.equal(keyTypeForAlgorithm("foo"), null);
	assert.equal(keyTypeForAlgorithm(null), null);
});

test("curvesForJWSAlgorithm (Curve.forJWSAlgorithm)", () => {
	assert.deepEqual(curvesForJWSAlgorithm("ES256"), ["P-256"]);
	assert.deepEqual(curvesForJWSAlgorithm("ES256K"), ["secp256k1"]);
	assert.deepEqual(curvesForJWSAlgorithm("ES384"), ["P-384"]);
	assert.deepEqual(curvesForJWSAlgorithm("ES512"), ["P-521"]);
	assert.deepEqual(curvesForJWSAlgorithm("EdDSA"), ["Ed25519", "Ed448"]);
	// Nimbus 10.9 has no curve set for the fully specified EdDSA algorithms: no restriction
	assert.equal(curvesForJWSAlgorithm("Ed25519"), null);
	assert.equal(curvesForJWSAlgorithm("Ed448"), null);
	assert.equal(curvesForJWSAlgorithm("RS256"), null);
	assert.equal(curvesForJWSAlgorithm("HS256"), null);
});

test("EC_CURVE_ALGORITHM (ECDSA.resolveAlgorithm)", () => {
	assert.deepEqual(
		{ ...EC_CURVE_ALGORITHM },
		{ "P-256": "ES256", secp256k1: "ES256K", "P-384": "ES384", "P-521": "ES512" },
	);
});

test("requireAlgorithmName: the NullPointerException of JWSAlgorithm.parse(null)", () => {
	assert.equal(requireAlgorithmName("RS256"), "RS256");
	assert.throws(() => requireAlgorithmName(null), {
		name: "TypeError",
		message: 'Cannot invoke "String.equals(Object)" because "s" is null',
	});
});

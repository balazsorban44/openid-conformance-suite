/**
 * Nimbus algorithm families (`JWSAlgorithm.Family`, `JWEAlgorithm.Family`, `EncryptionMethod.Family`) as explicit
 * lists, and the static Nimbus lookups keyed by an algorithm (`KeyType.forAlgorithm`, `Curve.forJWSAlgorithm`,
 * `ECDSA.resolveAlgorithm`). Algorithms are their names (strings).
 *
 * Mirrors nimbus-jose-jwt 10.9 (the version upstream's pom.xml pins).
 *
 * Not lock-tracked: there is no upstream Java file for this module.
 */

/** JWSAlgorithm.Family.HMAC_SHA */
export const JWS_FAMILY_HMAC_SHA: readonly string[] = ["HS256", "HS384", "HS512"];
/** JWSAlgorithm.Family.RSA */
export const JWS_FAMILY_RSA: readonly string[] = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];
/** JWSAlgorithm.Family.EC */
export const JWS_FAMILY_EC: readonly string[] = ["ES256", "ES256K", "ES384", "ES512"];
/** JWSAlgorithm.Family.ED */
export const JWS_FAMILY_ED: readonly string[] = ["EdDSA", "Ed25519", "Ed448"];
/** JWSAlgorithm.Family.SIGNATURE (RSA + EC + ED) */
export const JWS_FAMILY_SIGNATURE: readonly string[] = [...JWS_FAMILY_RSA, ...JWS_FAMILY_EC, ...JWS_FAMILY_ED];

/** JWEAlgorithm.Family.RSA */
export const JWE_FAMILY_RSA: readonly string[] = ["RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512"];
/** JWEAlgorithm.Family.AES_KW */
export const JWE_FAMILY_AES_KW: readonly string[] = ["A128KW", "A192KW", "A256KW"];
/** JWEAlgorithm.Family.ECDH_ES */
export const JWE_FAMILY_ECDH_ES: readonly string[] = ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"];
/** JWEAlgorithm.Family.ECDH_1PU */
export const JWE_FAMILY_ECDH_1PU: readonly string[] = [
	"ECDH-1PU",
	"ECDH-1PU+A128KW",
	"ECDH-1PU+A192KW",
	"ECDH-1PU+A256KW",
];
/** JWEAlgorithm.Family.AES_GCM_KW */
export const JWE_FAMILY_AES_GCM_KW: readonly string[] = ["A128GCMKW", "A192GCMKW", "A256GCMKW"];
/** JWEAlgorithm.Family.PBES2 */
export const JWE_FAMILY_PBES2: readonly string[] = ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"];
/** JWEAlgorithm.Family.ASYMMETRIC (RSA + ECDH_ES) */
export const JWE_FAMILY_ASYMMETRIC: readonly string[] = [...JWE_FAMILY_RSA, ...JWE_FAMILY_ECDH_ES];
/** JWEAlgorithm.Family.SYMMETRIC (AES_KW + AES_GCM_KW + dir) */
export const JWE_FAMILY_SYMMETRIC: readonly string[] = [...JWE_FAMILY_AES_KW, ...JWE_FAMILY_AES_GCM_KW, "dir"];

/** EncryptionMethod.Family.AES_CBC_HMAC_SHA */
export const ENC_FAMILY_AES_CBC_HMAC_SHA: readonly string[] = ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"];
/** EncryptionMethod.Family.AES_GCM */
export const ENC_FAMILY_AES_GCM: readonly string[] = ["A128GCM", "A192GCM", "A256GCM"];

/**
 * Nimbus `JWSAlgorithm.parse(null)` / `JWEAlgorithm.parse(null)` / `EncryptionMethod.parse(null)` throw a
 * NullPointerException; the predicates built on them do the same.
 */
export function requireAlgorithmName(name: string | null | undefined): string {
	if (name == null) {
		throw new TypeError('Cannot invoke "String.equals(Object)" because "s" is null');
	}
	return name;
}

/**
 * Nimbus `KeyType.forAlgorithm(Algorithm)`: the `kty` a key for the given JWS or JWE algorithm must have, or null
 * for null / an unknown algorithm.
 *
 * Unified from four copies: AbstractVerifyJwsSignature, AbstractValidateJWKs and ValidateRequestObjectSignature had
 * a JWS-only subset (RSA, EC, HMAC_SHA, ED), AbstractVerifyJweEncryption the full method. For every JWS algorithm
 * the results are the same; the JWS-only copies returned null for a JWE algorithm name where Nimbus returns a key
 * type. No caller relied on that: AbstractVerifyJwsSignature only calls it after `JWAUtil.isJwsAlgorithm`, and
 * {@link import("./jws.ts").selectJWSJwks} checks the JWS family first, as `JWKMatcher.forJWSHeader` does.
 */
export function keyTypeForAlgorithm(alg: string | null | undefined): "RSA" | "EC" | "oct" | "OKP" | null {
	if (alg == null) {
		return null;
	}
	if (JWS_FAMILY_RSA.includes(alg)) {
		return "RSA";
	} else if (JWS_FAMILY_EC.includes(alg)) {
		return "EC";
	} else if (JWS_FAMILY_HMAC_SHA.includes(alg)) {
		return "oct";
	} else if (JWE_FAMILY_RSA.includes(alg)) {
		return "RSA";
	} else if (JWE_FAMILY_ECDH_ES.includes(alg)) {
		return "EC";
	} else if ("dir" === alg) {
		return "oct";
	} else if (JWE_FAMILY_AES_GCM_KW.includes(alg)) {
		return "oct";
	} else if (JWE_FAMILY_AES_KW.includes(alg)) {
		return "oct";
	} else if (JWE_FAMILY_PBES2.includes(alg)) {
		return "oct";
	} else if (JWS_FAMILY_ED.includes(alg)) {
		return "OKP";
	}
	return null;
}

/**
 * Nimbus `Curve.forJWSAlgorithm(JWSAlgorithm)`: the curves a key for the given JWS algorithm may be on, or null when
 * Nimbus does not restrict them (which `JWKMatcher` treats as "any curve").
 *
 * Unified from three copies that disagreed for the fully specified EdDSA algorithms: AbstractVerifyJwsSignature
 * returned [Ed25519] for `Ed25519` and [Ed448] for `Ed448`, AbstractValidateJWKs [Ed25519] for `Ed25519` and
 * [Ed25519, Ed448] for every other ED name, ValidateRequestObjectSignature null for both. Nimbus 10.9 only maps
 * ES256/ES256K/ES384/ES512 and `EdDSA` (to [Ed25519, Ed448]) and returns null for `Ed25519` and `Ed448`, so the
 * ValidateRequestObjectSignature behaviour is kept. For the other two conditions the extra keys never reach a log:
 * they only build a verifier for an OKP key on Ed25519 (an Ed448 key is skipped), and jose refuses to import an
 * Ed25519 key for `alg: Ed448` (the import failure is treated as "no verifier", as before).
 */
export function curvesForJWSAlgorithm(alg: string): string[] | null {
	switch (alg) {
		case "ES256":
			return ["P-256"];
		case "ES256K":
			return ["secp256k1"];
		case "ES384":
			return ["P-384"];
		case "ES512":
			return ["P-521"];
		case "EdDSA":
			return ["Ed25519", "Ed448"];
		default:
			return null;
	}
}

/**
 * Nimbus `ECDSA.resolveAlgorithm(Curve)`: the only JWS algorithm an `ECDSASigner` / `ECDSAVerifier` for a key on
 * this curve supports. (Three identical copies before: AbstractSignJWT, AbstractVerifyJwsSignature,
 * ValidateRequestObjectSignature.)
 */
export const EC_CURVE_ALGORITHM: Readonly<Record<string, string>> = {
	"P-256": "ES256",
	secp256k1: "ES256K",
	"P-384": "ES384",
	"P-521": "ES512",
};

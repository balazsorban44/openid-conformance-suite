/**
 * Nimbus algorithm families (`JWSAlgorithm.Family`, `JWEAlgorithm.Family`, `EncryptionMethod.Family`) as explicit
 * lists, and the static Nimbus lookups keyed by an algorithm (`KeyType.forAlgorithm`, `Curve.forJWSAlgorithm`,
 * `ECDSA.resolveAlgorithm`). Algorithms are their names (strings).
 *
 * Mirrors nimbus-jose-jwt 10.9 (the version upstream's pom.xml pins). Also the algorithm checks of upstream's
 * util/JWAUtil and util/JWSUtil.
 */
import { NamedError } from "./errors.ts";

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
 * type. No caller relied on that: AbstractVerifyJwsSignature only calls it after `isJwsAlgorithm`, and
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

/** JWAUtil.InvalidAlgorithmException */
export class InvalidAlgorithmException extends NamedError {
	constructor(algorithm: string) {
		super("Invalid algorithm:" + algorithm);
	}
}

/**
 * Is this the name of a JWS algorithm whose signature can be verified?
 *
 * <p>True only for the algorithms registered for JWS use in the IANA "JSON Web Signature and
 * Encryption Algorithms" registry that have a key type: the digital signature algorithms
 * (RS*, PS*, ES*, EdDSA, Ed25519, Ed448) and the MAC algorithms (HS*), both of which AuthZEN
 * and the JOSE specs allow for signing.
 *
 * <p>False for `none`, for unregistered names, and — importantly — for the JWE key
 * management algorithms (`dir`, `A128KW`, `RSA-OAEP-256`, `ECDH-ES`,
 * `PBES2-*`). Those last ones matter because {@link com.nimbusds.jose.jwk.KeyType#forAlgorithm}
 * happily maps them onto a key type, so a plain "does this algorithm have a key type" test would
 * accept a JWE algorithm in a JWS header.
 *
 * @param algorithm the 'alg' header value (may be null or empty)
 * @return true if a JWS signature made with this algorithm could be verified
 *
 * upstream: util/JWAUtil.java
 */
export function isJwsAlgorithm(algorithm: string | null | undefined): boolean {
	if (!algorithm) {
		return false;
	}
	return JWS_FAMILY_SIGNATURE.includes(algorithm) || JWS_FAMILY_HMAC_SHA.includes(algorithm);
}

/**
 * Returns the Java digest algorithm name ("SHA-256", "SHA-384", "SHA-512"). For node:crypto use
 * `createHash(name.replace("-", "").toLowerCase())`.
 *
 * @throws InvalidAlgorithmException
 *
 * upstream: util/JWAUtil.java
 */
export function getDigestAlgorithmForSigAlg(signatureAlgorithm: string): string {
	if ("EdDSA" === signatureAlgorithm || "Ed25519" === signatureAlgorithm) {
		return "SHA-512";
	} else if (signatureAlgorithm.startsWith("ES") && signatureAlgorithm.endsWith("K")) {
		const matcher = /^(ES)(256|384|512)K$/.exec(signatureAlgorithm);
		if (!matcher) {
			throw new InvalidAlgorithmException(signatureAlgorithm);
		}
		return "SHA-" + matcher[2];
	} else {
		const matcher = /^(HS|RS|ES|PS)(256|384|512)$/.exec(signatureAlgorithm);
		if (!matcher) {
			throw new InvalidAlgorithmException(signatureAlgorithm);
		}
		return "SHA-" + matcher[2];
	}
}

/**
 * Asymmetric JWS algorithms registered in the IANA JOSE Algorithms registry that are
 * not yet exposed by Nimbus families. The Nimbus EC/ED/RSA families miss these recently
 * registered post-quantum and revised algorithm names; until the dependency catches up
 * we treat membership in this set as equivalent to membership in the Nimbus families.
 *
 * @see <a href="https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms">IANA JOSE Algorithms registry</a>
 */
const EXTRA_ASYMMETRIC_JWS_ALGORITHMS: readonly string[] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

/**
 * Checks if alg is one of the algorithms supported by Nimbusds
 * @param alg
 * @return
 *
 * upstream: util/JWSUtil.java
 */
export function isValidJWSAlgorithm(alg: string | null | undefined): boolean {
	alg = requireAlgorithmName(alg);
	if (
		JWS_FAMILY_EC.includes(alg) ||
		JWS_FAMILY_ED.includes(alg) ||
		JWS_FAMILY_HMAC_SHA.includes(alg) ||
		JWS_FAMILY_RSA.includes(alg)
	) {
		return true;
	}
	return EXTRA_ASYMMETRIC_JWS_ALGORITHMS.includes(alg);
}

/**
 * Checks if alg is an asymmetric algorithm
 * @param alg
 * @return
 *
 * upstream: util/JWSUtil.java
 */
export function isAsymmetricJWSAlgorithm(alg: string | null | undefined): boolean {
	alg = requireAlgorithmName(alg);
	if (JWS_FAMILY_EC.includes(alg) || JWS_FAMILY_ED.includes(alg) || JWS_FAMILY_RSA.includes(alg)) {
		return true;
	}
	return EXTRA_ASYMMETRIC_JWS_ALGORITHMS.includes(alg);
}

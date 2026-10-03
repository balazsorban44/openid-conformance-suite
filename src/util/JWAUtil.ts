import { JWS_FAMILY_HMAC_SHA, JWS_FAMILY_SIGNATURE } from "./nimbus/algorithms.ts";
import { NamedError } from "../framework/NamedError.ts";

export class InvalidAlgorithmException extends NamedError {
	constructor(algorithm: string) {
		super("Invalid algorithm:" + algorithm);
	}
}

export class JWAUtil {
	/** Alias so `JWAUtil.InvalidAlgorithmException` works as in Java; the type is the exported {@link InvalidAlgorithmException}. */
	static readonly InvalidAlgorithmException = InvalidAlgorithmException;

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
	 */
	static isJwsAlgorithm(algorithm: string | null | undefined): boolean {
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
	 */
	static getDigestAlgorithmForSigAlg(signatureAlgorithm: string): string {
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
}

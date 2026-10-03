/**
 * Nimbus JWS signing and verification on top of jose: the `JWSSigner` implementations (`RSASSASigner`,
 * `ECDSASigner`, `MACSigner`, `Ed25519Signer`, `DefaultJWSSignerFactory`), the checks the `JWSVerifier`
 * implementations make before verifying (`RSASSAVerifier`, `ECDSAVerifier`, `MACVerifier`, `Ed25519Verifier`),
 * `AlgorithmSupportMessage`, and upstream's `extensions/AlternateJWSVerificationKeySelector.selectJWSJwks`.
 * (AlternateJWSVerificationKeySelector's one method lives here because it is pure Nimbus key selection).
 */
import { CompactSign, compactVerify, errors, type CompactJWSHeaderParameters, type CryptoKey } from "jose";
import { type JsonObject } from "./json.ts";
import {
	EC_CURVE_ALGORITHM,
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
} from "./jose-algorithms.ts";
import { expectedClass, JOSEException, KeyLengthException } from "./errors.ts";
import { importKey, isPrivate, jwkMatcherForJWSHeader, toPublicJWK, type JWK, type JWKSet } from "./jose-jwk.ts";
import { type JWT } from "./jose-jwt.ts";

/** Nimbus `AlgorithmSupportMessage.itemize`: "a", "a or b", "a, b or c" */
function itemize(items: readonly string[]): string {
	let out = "";
	for (let i = 0; i < items.length; i++) {
		if (i > 0) {
			out += i === items.length - 1 ? " or " : ", ";
		}
		out += items[i];
	}
	return out;
}

/** Nimbus `AlgorithmSupportMessage.unsupportedJWSAlgorithm` (was local to AbstractVerifyJwsSignature) */
export function unsupportedJWSAlgorithm(alg: string, supported: readonly string[]): string {
	return "Unsupported JWS algorithm " + alg + ", must be " + itemize(supported);
}

/** Ed25519Signer.SUPPORTED_ALGORITHMS / Ed25519Verifier.SUPPORTED_ALGORITHMS */
const ED25519_ALGORITHMS: readonly string[] = ["EdDSA", "Ed25519"];

/** Nimbus `new RSASSASigner((RSAKey) jwk)` */
export function rsaSigner(jwk: JWK): JWSSigner {
	if (!isPrivate(jwk)) {
		throw new JOSEException("The RSA JWK doesn't contain a private part");
	}
	return new JWSSigner("RSASSASigner", jwk, JWS_FAMILY_RSA);
}

/** Nimbus `new ECDSASigner((ECKey) jwk)` */
export function ecSigner(jwk: JWK): JWSSigner {
	const crv = jwk["crv"];
	if (crv == null) {
		throw new JOSEException("The EC key curve is not supported, must be P-256, P-384 or P-521");
	}
	const alg = EC_CURVE_ALGORITHM[crv];
	if (alg == null) {
		throw new JOSEException("Unexpected curve: " + crv);
	}
	if (!isPrivate(jwk)) {
		throw new JOSEException("The EC JWK doesn't contain a private part");
	}
	return new JWSSigner("ECDSASigner", jwk, [alg]);
}

/** Nimbus `new MACSigner((OctetSequenceKey) jwk)` */
export function macSigner(jwk: JWK): JWSSigner {
	const bitLength = Buffer.from(String(jwk["k"] ?? ""), "base64url").length * 8;
	if (bitLength < 256) {
		throw new KeyLengthException("The secret length must be at least 256 bits");
	}
	// MACSigner.getCompatibleAlgorithms
	const algorithms: string[] = [];
	if (bitLength >= 256) {
		algorithms.push("HS256");
	}
	if (bitLength >= 384) {
		algorithms.push("HS384");
	}
	if (bitLength >= 512) {
		algorithms.push("HS512");
	}
	return new JWSSigner("MACSigner", jwk, algorithms);
}

/** Nimbus `new Ed25519Signer((OctetKeyPair) jwk)` */
export function ed25519Signer(jwk: JWK): JWSSigner {
	if (jwk["crv"] !== "Ed25519") {
		throw new JOSEException("Ed25519Signer only supports OctetKeyPairs with crv=Ed25519");
	}
	if (!isPrivate(jwk)) {
		throw new JOSEException("The OctetKeyPair doesn't contain a private part");
	}
	return new JWSSigner("Ed25519Signer", jwk, ED25519_ALGORITHMS);
}

/**
 * Nimbus `DefaultJWSSignerFactory.createJWSSigner(jwk, alg)` (also what `MultiJWSSignerFactory` falls back to).
 *
 * @throws JOSEException
 */
export function createJWSSigner(jwk: JWK, alg: string): JWSSigner {
	if (!isPrivate(jwk)) {
		throw new JOSEException("Expected private JWK but none available");
	}
	if (jwk["use"] != null && jwk["use"] !== "sig") {
		throw new JOSEException("The JWK use must be sig (signature) or unspecified");
	}
	if (JWS_FAMILY_HMAC_SHA.includes(alg)) {
		if (jwk["kty"] !== "oct") {
			throw expectedClass("OctetSequenceKey");
		}
		return macSigner(jwk);
	} else if (JWS_FAMILY_RSA.includes(alg)) {
		if (jwk["kty"] !== "RSA") {
			throw expectedClass("RSAKey");
		}
		return rsaSigner(jwk);
	} else if (JWS_FAMILY_EC.includes(alg)) {
		if (jwk["kty"] !== "EC") {
			throw expectedClass("ECKey");
		}
		return ecSigner(jwk);
	} else if (JWS_FAMILY_ED.includes(alg)) {
		if (jwk["kty"] !== "OKP") {
			throw expectedClass("OctetKeyPair");
		}
		return ed25519Signer(jwk);
	}
	throw new JOSEException("Unsupported JWS algorithm: " + alg);
}

/**
 * Replaces the Nimbus `JWSSigner` implementations used by the conformance suite (`RSASSASigner`, `ECDSASigner`,
 * `MACSigner`, `Ed25519Signer`) on top of jose. `new SignedJWT(header, claimSet).sign(signer); serialize()` becomes
 * `await signer.sign(header, payload)`. (Was defined in AbstractSignJWT.)
 */
export class JWSSigner {
	/** The Nimbus class name (Java `getClass().getSimpleName()`). */
	readonly name: string;
	readonly jwk: JWK;
	private readonly algorithms: readonly string[];

	constructor(name: string, jwk: JWK, algorithms: readonly string[]) {
		this.name = name;
		this.jwk = jwk;
		this.algorithms = algorithms;
	}

	/** Nimbus `JWSProvider.supportedJWSAlgorithms()` */
	supportedJWSAlgorithms(): readonly string[] {
		return this.algorithms;
	}

	/**
	 * Signs `payload` with the given (protected) JWS header and returns the compact serialization.
	 * Replaces Nimbus `JWSObject.sign(signer)` + `serialize()`.
	 *
	 * @throws JOSEException (or a jose error)
	 */
	async sign(header: JsonObject, payload: string | Uint8Array): Promise<string> {
		const alg = header["alg"] as string;
		// JWSObject.ensureJWSSignerSupport
		if (!this.algorithms.includes(alg)) {
			throw new JOSEException(
				"The " +
					alg +
					" algorithm is not allowed or supported by the JWS signer: Supported algorithms: [" +
					this.algorithms.join(", ") +
					"]",
			);
		}
		const key = await importKey(this.jwk, alg);
		const bytes = typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
		return await new CompactSign(bytes).setProtectedHeader(header as CompactJWSHeaderParameters).sign(key);
	}
}

/**
 * Port of upstream's `extensions/AlternateJWSVerificationKeySelector.selectJWSJwks(header, context)` over an
 * `ImmutableJWKSet` (the only way the conditions use it, always constructed with the header's own algorithm): the
 * keys {@link jwkMatcherForJWSHeader} (Nimbus `JWKMatcher.forJWSHeader`) accepts, each asymmetric key as its public
 * JWK (followed by the key itself when it is private), each secret key as is. Empty for an unsupported algorithm.
 *
 * Unified from three copies that differed in the matcher:
 * - `x5t#S256` in the header: ValidateRequestObjectSignature matched it the way `JWKMatcher.matches` does (the key's
 *   own `x5t#S256` or the thumbprint of its first `x5c` certificate); AbstractVerifyJwsSignature only compared the
 *   key's `x5t#S256`; AbstractValidateJWKs ignored it. The Nimbus behaviour is kept. AbstractVerifyJwsSignature
 *   already filters by the key's `x5t#S256` before it calls this, and AbstractValidateJWKs verifies a JWS it signed
 *   itself without `x5t#S256`, so neither condition sees a different key list.
 * - `kid`: AbstractValidateJWKs took any header `kid` value, the others only a string one; a parsed (or, there,
 *   self-built) header always has a string `kid`, so the string-only form is kept.
 * - curves for the ED family: see {@link import("./algorithms.ts").curvesForJWSAlgorithm}.
 */
export function selectJWSJwks(header: JsonObject, jwkSet: JWKSet): JWK[] {
	const matcher = jwkMatcherForJWSHeader(header);
	if (matcher == null) {
		return [];
	}
	const jwkMatches = jwkSet.keys.filter(matcher);
	// Get non-EdDSA keys from original function
	const sanitizedJWKs: JWK[] = [];
	for (const jwk of jwkMatches) {
		if (jwk["kty"] === "RSA" || jwk["kty"] === "EC" || jwk["kty"] === "OKP") {
			// AsymmetricJWK
			sanitizedJWKs.push(toPublicJWK(jwk) as JWK);
			if (isPrivate(jwk)) {
				sanitizedJWKs.push(jwk);
			}
		} else if (jwk["kty"] === "oct") {
			// SecretJWK
			sanitizedJWKs.push(jwk);
		}
	}
	return sanitizedJWKs;
}

/** Nimbus `MACProvider.getMinRequiredSecretLength` */
const MAC_MIN_SECRET_BITS: Readonly<Record<string, number>> = { HS256: 256, HS384: 384, HS512: 512 };

/** Critical header params the Nimbus verifiers process themselves (`CriticalHeaderParamsDeferral`) */
const PROCESSED_CRITICAL_HEADER_PARAMS: readonly string[] = ["b64"];

/**
 * A JWS verifier: the jose key, plus the JWK it was built from (only its `kty` and `crv` are used, to apply the
 * checks of the Nimbus verifier class for that key type). Replaces the Nimbus `JWSVerifier` implementations.
 */
export interface JWSVerifier {
	jwk: JsonObject;
	key: CryptoKey | Uint8Array;
}

/**
 * Nimbus `SignedJWT.verify(verifier)`: the verifier's own checks first (they throw a JOSEException), false for
 * unprocessed critical header parameters, then the signature check (false when it does not verify).
 *
 * - EC (`ECDSAVerifier`): the header `alg` must be the one of the key's curve (`ECDSA.resolveAlgorithm`).
 * - OKP (`Ed25519Verifier`): the header `alg` must be EdDSA or Ed25519.
 * - oct (`MACVerifier`): the secret must be at least as long as the header `alg` requires.
 *
 * Unified from the copies in ValidateRequestObjectSignature (this one, unchanged except that the MAC length error is
 * now the Nimbus KeyLengthException subclass, same message) and AbstractVerifyJwsSignature (`verifyWith`), which
 * made no verifier check of its own (the EC one is made by the condition before), verified `jwt.serialized`
 * (untrimmed) rather than the parsed parts, returned false for any jose `JWSInvalid` and threw for an unrecognised
 * `crit` parameter. Kept: the Nimbus behaviour, which is what the Java conditions hit. For AbstractVerifyJwsSignature
 * this means: an HMAC secret too short for HS384/HS512 is the KeyLengthException "The secret length for HS384 must
 * be at least 384 bits" (was: "does not verify"); an unrecognised `crit` parameter is "does not verify" (was: a
 * JOSEException); any other jose `JWSInvalid` is a JOSEException (was: "does not verify").
 *
 * jose rejects some keys/inputs Nimbus accepts (e.g. RSA keys shorter than 2048 bits); anything jose throws other
 * than a signature mismatch is reported as a JOSEException, like Nimbus' `verify()` would.
 *
 * @throws JOSEException
 */
export async function verifySignedJWT(jwt: JWT, verifier: JWSVerifier): Promise<boolean> {
	const alg = jwt.header["alg"] as string;
	const kty = verifier.jwk["kty"];
	if (kty === "EC") {
		const supported = EC_CURVE_ALGORITHM[verifier.jwk["crv"] as string];
		if (alg !== supported) {
			throw new JOSEException(unsupportedJWSAlgorithm(alg, [supported]));
		}
	} else if (kty === "OKP") {
		if (!ED25519_ALGORITHMS.includes(alg)) {
			throw new JOSEException("Ed25519Verifier requires alg=Ed25519 or alg=EdDSA in JWSHeader");
		}
	} else if (kty === "oct") {
		const minRequiredBitLength = MAC_MIN_SECRET_BITS[alg];
		if (minRequiredBitLength == null) {
			throw new JOSEException(unsupportedJWSAlgorithm(alg, JWS_FAMILY_HMAC_SHA));
		}
		if ((verifier.key as Uint8Array).length * 8 < minRequiredBitLength) {
			throw new KeyLengthException(
				"The secret length for " + alg + " must be at least " + minRequiredBitLength + " bits",
			);
		}
	}
	const crit = jwt.header["crit"];
	if (Array.isArray(crit) && crit.some((p) => !PROCESSED_CRITICAL_HEADER_PARAMS.includes(p as string))) {
		return false;
	}
	try {
		await compactVerify(jwt.parts.join("."), verifier.key, { algorithms: [alg] });
		return true;
	} catch (e) {
		if (e instanceof errors.JWSSignatureVerificationFailed) {
			return false;
		}
		throw new JOSEException((e as Error).message, { cause: e });
	}
}

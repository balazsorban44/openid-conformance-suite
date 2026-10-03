import { compactVerify, errors } from "jose";
import { args, type JsonObject } from "../../framework/index.ts";
import { AbstractLenientJwksCondition } from "../AbstractLenientJwksCondition.ts";
import { JWAUtil } from "../../util/JWAUtil.ts";
import { JOSEException, KeyLengthException } from "../../util/JWEUtil.ts";
import {
	JWKUtil,
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
	ParseException,
	type JWK,
	type JWKSet,
} from "../../util/JWKUtil.ts";
import { JWTUtil, type JWT } from "../../util/JWTUtil.ts";

/** A parsed JWS (replaces Nimbus SignedJWT): `jwt.header` is the protected header, `jwt.serialized` the compact JWS. */
export type SignedJWT = JWT;

/**
 * Nimbus `SignedJWT.parse(String)`.
 *
 * TS: JWTUtil has no SignedJWT.parse equivalent, so the JWTParser port is used and anything that is not a JWS is
 * rejected with the message SignedJWT.parse would give. (JWTUtil.parseJWT additionally rejects characters outside
 * base64url and '.', which SignedJWT.parse rejects with a different message.)
 *
 * @throws ParseException
 */
function parseSignedJWT(token: string): SignedJWT {
	const jwt = JWTUtil.parseJWT(token);
	if (jwt.type === "encrypted") {
		throw new ParseException("Unexpected number of Base64URL parts, must be three");
	}
	if (jwt.type !== "signed") {
		throw new ParseException("Invalid JWS header: Not a JWS header");
	}
	return jwt;
}

/** Nimbus `KeyType.forAlgorithm(JWSAlgorithm)` */
function keyTypeForJWSAlgorithm(alg: string): string | null {
	if (JWS_FAMILY_RSA.includes(alg)) {
		return "RSA";
	} else if (JWS_FAMILY_EC.includes(alg)) {
		return "EC";
	} else if (JWS_FAMILY_HMAC_SHA.includes(alg)) {
		return "oct";
	} else if (JWS_FAMILY_ED.includes(alg)) {
		return "OKP";
	}
	return null;
}

/** Nimbus `Curve.forJWSAlgorithm` for the ED family */
function curvesForEdAlgorithm(alg: string): string[] {
	if (alg === "Ed25519") {
		return ["Ed25519"];
	} else if (alg === "Ed448") {
		return ["Ed448"];
	}
	return ["Ed25519", "Ed448"];
}

/** Nimbus `ECDSA.resolveAlgorithm(Curve)`: the only JWS algorithm an ECDSAVerifier for a key on this curve supports */
const EC_CURVE_ALGORITHM: Record<string, string> = {
	"P-256": "ES256",
	secp256k1: "ES256K",
	"P-384": "ES384",
	"P-521": "ES512",
};

/** Nimbus `AlgorithmSupportMessage.itemize` */
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

/** Nimbus `AlgorithmSupportMessage.unsupportedJWSAlgorithm` */
function unsupportedJWSAlgorithm(alg: string, supported: readonly string[]): string {
	return "Unsupported JWS algorithm " + alg + ", must be " + itemize(supported);
}

/**
 * Port of extensions/AlternateJWSVerificationKeySelector.selectJWSJwks: Nimbus `JWKMatcher.forJWSHeader(header)`
 * applied to the keys of `jwkSet`, then the asymmetric keys are returned as their public key (plus the key itself if
 * it is private) and the secret keys as is. Returns an empty list for an unsupported algorithm.
 */
function selectJWSJwks(header: JsonObject, jwkSet: JWKSet): JWK[] {
	const alg = header["alg"] as string;
	const kid = typeof header["kid"] === "string" ? header["kid"] : null;
	const x5tS256 = typeof header["x5t#S256"] === "string" ? header["x5t#S256"] : null;
	const kty = keyTypeForJWSAlgorithm(alg);
	if (kty == null) {
		return [];
	}
	const jwkMatches: JWK[] = [];
	for (const jwk of jwkSet.keys) {
		if (jwk["kty"] !== kty) {
			continue;
		}
		if (kid != null && jwk["kid"] !== kid) {
			continue;
		}
		if (jwk["alg"] != null && jwk["alg"] !== alg) {
			continue;
		}
		if (kty === "oct") {
			// privateOnly(true) - symmetric keys are always private; no 'use' restriction for HMAC
		} else {
			if (jwk["use"] != null && jwk["use"] !== "sig") {
				continue;
			}
			if ((kty === "RSA" || kty === "EC") && x5tS256 != null && jwk["x5t#S256"] !== x5tS256) {
				continue;
			}
			if (kty === "OKP" && !curvesForEdAlgorithm(alg).includes(jwk["crv"] as string)) {
				continue;
			}
		}
		jwkMatches.push(jwk);
	}
	// Get non-EdDSA keys from original function
	const sanitizedJWKs: JWK[] = [];
	for (const jwk of jwkMatches) {
		if (jwk["kty"] !== "oct") {
			sanitizedJWKs.push(JWKUtil.toPublicJWK(jwk) as JWK);
			if (JWKUtil.isPrivate(jwk)) {
				sanitizedJWKs.push(jwk);
			}
		} else {
			sanitizedJWKs.push(jwk);
		}
	}
	return sanitizedJWKs;
}

/** A jose verification key (replaces Nimbus JWSVerifier) */
type JWSVerifier = Awaited<ReturnType<typeof JWKUtil.importKey>>;

/**
 * `jwt.verify(verifier)`: true if the signature is valid, false if not.
 *
 * Nimbus verifiers return false (rather than throwing) for a header carrying unsupported critical parameters; jose
 * throws JWSInvalid for those, which is mapped to false as well. Anything else jose rejects is a JOSEException.
 *
 * @throws JOSEException
 */
async function verifyWith(jwt: SignedJWT, verifier: JWSVerifier): Promise<boolean> {
	const alg = jwt.header["alg"] as string;
	try {
		await compactVerify(jwt.serialized, verifier, { algorithms: [alg] });
		return true;
	} catch (e) {
		if (e instanceof errors.JWSSignatureVerificationFailed || e instanceof errors.JWSInvalid) {
			return false;
		}
		// TS: e.g. jose refuses RSA keys shorter than 2048 bits (TypeError), which Nimbus' RSASSAVerifier accepts
		throw new JOSEException(e instanceof Error ? e.message : String(e), { cause: e });
	}
}

export abstract class AbstractVerifyJwsSignature extends AbstractLenientJwksCondition {
	protected async verifyJwsSignature(
		token: string,
		publicJwks: JsonObject,
		tokenName: string,
		kidRequired: boolean,
		jwksName: string,
	): Promise<void> {
		try {
			// translate stored items into nimbus objects
			const jwt = parseSignedJWT(token);
			// parse leniently: skip keys the JOSE library cannot handle (e.g. unsupported curves
			// like Brainpool, or future PQ algorithms) so an unusable key elsewhere in the set does
			// not abort verification when a usable signing key is present; skipped keys are logged
			const jwkSet = this.parseJwksLenientlyLoggingSkips(JSON.stringify(publicJwks), jwksName);
			let jwkSetWithKeyValid: JWKSet | null = null;

			const header = jwt.header;
			const headerKeyID = typeof header["kid"] === "string" ? header["kid"] : null;
			const headerAlg = typeof header["alg"] === "string" ? header["alg"] : null;
			// Only a registered JWS signature or MAC algorithm names a key that could verify this
			// signature. KeyType.forAlgorithm() is not a sufficient test on its own: it maps the JWE
			// key management algorithms onto a key type too ('dir' and 'A128KW' to oct, 'RSA-OAEP-256'
			// to RSA), and it returns null for an unregistered name, which used to be dereferenced
			// below and crash the test with an internal error instead of failing the condition.
			if (!JWAUtil.isJwsAlgorithm(headerAlg)) {
				throw this.error(
					"The '" +
						tokenName +
						"' JWS header 'alg' is not a registered JWS signature or MAC " +
						"algorithm, so its signature cannot be verified",
					args("alg", headerAlg, tokenName, token),
				);
			}
			const alg = headerAlg as string;
			const headerKty = keyTypeForJWSAlgorithm(alg) as string;
			const headerX509CertSha256Thumbprint = typeof header["x5t#S256"] === "string" ? header["x5t#S256"] : null;

			let numberOfKeyValid = 0;
			for (const jwkKey of jwkSet.keys) {
				if (
					headerKeyID != null &&
					headerKeyID === jwkKey["kid"] &&
					jwkKey["alg"] != null &&
					jwkKey["alg"] === alg &&
					"sig" === jwkKey["use"] &&
					jwkKey["kty"] === headerKty
				) {
					numberOfKeyValid++;
					if (numberOfKeyValid > 1) {
						throw this.error(
							"Found more than one key in " + jwksName + " JWKS that has the right kid, kty, alg and 'use':'sig'",
							args("jwks", publicJwks, "kid", headerKeyID, "alg", alg, "kty", headerKty, tokenName, token),
						);
					}
				}
			}

			let key: JWK | null = null;
			// if a kid is given
			if (headerKeyID) {
				for (const jwkKey of jwkSet.keys) {
					if (headerKeyID === jwkKey["kid"]) {
						if (!this.isSelectedJWKKeyBaseOnJWSHeader(alg, headerKty, headerX509CertSha256Thumbprint, jwkKey)) {
							continue;
						}

						key = jwkKey;
						if (await this.verifySignature(jwt, { keys: [jwkKey] } as JWKSet)) {
							// save key which is able to verify
							jwkSetWithKeyValid = { keys: [jwkKey] } as JWKSet;
							break;
						} else {
							throw this.error(
								"Unable to verify " +
									tokenName +
									" signature based on " +
									jwksName +
									" key with the correct kid, kty that also matches (or does not have) alg/x5t#S256/'use':'sig'",
								args("jwks", publicJwks, "kid", headerKeyID, "alg", alg, "kty", headerKty, tokenName, token),
							);
						}
					}
				}
				if (key == null) {
					throw this.error(
						jwksName +
							" JWKS does not contain a key with the correct kid, kty that also matches (or does not have) alg/x5t#S256/'use':'sig'",
						args("jwks", publicJwks, "kid", headerKeyID, "alg", alg, "kty", headerKty, tokenName, token),
					);
				}
			} else {
				// if a kid isn't given
				if (kidRequired) {
					throw this.error("kid value in JWT header is missing/null/empty");
				}
				let validSignature = false;
				for (const jwkKey of jwkSet.keys) {
					if (!this.isSelectedJWKKeyBaseOnJWSHeader(alg, headerKty, headerX509CertSha256Thumbprint, jwkKey)) {
						continue;
					}

					key = jwkKey;
					if (await this.verifySignature(jwt, { keys: [jwkKey] } as JWKSet)) {
						// save key which is able to verify
						jwkSetWithKeyValid = { keys: [jwkKey] } as JWKSet;
						validSignature = true;
						break;
					}
				}
				if (key == null) {
					throw this.error(
						jwksName +
							" JWKS does not contain a key with the correct kty that also matches (or does not have) alg/x5t#S256/'use':'sig'",
						args("jwks", publicJwks, "kid", headerKeyID, "alg", alg, "kty", headerKty, tokenName, token),
					);
				}
				if (!validSignature) {
					throw this.error(
						"Unable to verify " + tokenName + " signature based on " + jwksName + " keys",
						args("jwks", publicJwks, tokenName, token),
					);
				}
			}

			// JWKSet.toPublicJWKSet() drops the symmetric keys
			const publicKey = JWKUtil.toPublicJWK((jwkSetWithKeyValid as JWKSet).keys[0]);
			const publicKeySetString = publicKey != null ? JSON.stringify(publicKey) : null;
			const tokenObject: JsonObject = {};
			tokenObject["verifiable_jws"] = token;
			tokenObject["public_jwk"] = publicKeySetString;
			this.logSuccess(tokenName + " signature validated", args(tokenName, tokenObject));
		} catch (e) {
			if (e instanceof JOSEException || e instanceof ParseException) {
				throw this.error("Error validating " + tokenName + " signature", e);
			}
			throw e;
		}
	}

	private isSelectedJWKKeyBaseOnJWSHeader(
		headerAlg: string,
		headerKty: string,
		headerX509CertSha256Thumbprint: string | null,
		jwkKey: JWK,
	): boolean {
		// filter by 'kty'
		if (jwkKey["kty"] !== headerKty) {
			return false;
		}

		// filter by 'alg' if key has alg (matching the token alg)
		if (jwkKey["alg"] != null && headerAlg !== jwkKey["alg"]) {
			return false;
		}

		// filter by 'use: sig' (if 'use' present in server key)
		if (jwkKey["use"] != null && "sig" !== jwkKey["use"]) {
			return false;
		}

		// filter by 'x5t#S256' (if 'x5t#S256' present in JWS header)
		// UPSTREAM: Java dereferences jwkKey.getX509CertSHA256Thumbprint() without a null check, so a key without
		// x5t#S256 throws a NullPointerException when the JWS header has x5t#S256; the TypeError below mirrors that.
		if (
			headerX509CertSha256Thumbprint != null &&
			headerX509CertSha256Thumbprint !== (jwkKey["x5t#S256"] as unknown as { toString(): string }).toString()
		) {
			return false;
		}

		return true;
	}

	/** @throws JOSEException */
	protected async verifySignature(jwt: SignedJWT, jwkSet: JWKSet): Promise<boolean> {
		const alg = jwt.header["alg"] as string;

		const jwkKeys = selectJWSJwks(jwt.header, jwkSet);

		for (const jwkKey of jwkKeys) {
			let verifier: JWSVerifier | null = null;
			// the algorithm the verifier supports (an ECDSAVerifier only supports the one matching the key's curve)
			let verifierAlg = alg;
			try {
				if (jwkKey["kty"] === "OKP") {
					const publicKey = JWKUtil.parseJWK(JSON.stringify(JWKUtil.toPublicJWK(jwkKey)));
					if ("Ed25519" === publicKey["crv"]) {
						verifier = await JWKUtil.importKey(publicKey, alg);
					} // else Unsupported Curve, throw exception?
				} else if (jwkKey["kty"] === "RSA" || jwkKey["kty"] === "EC") {
					// toKeyPair().getPublic(); DefaultJWSVerifierFactory.createJWSVerifier(header, publicKey)
					const publicKey = JWKUtil.toPublicJWK(jwkKey) as JWK;
					if (publicKey["kty"] === "EC") {
						verifierAlg = EC_CURVE_ALGORITHM[publicKey["crv"] as string] ?? alg;
					}
					// TS: jose does not support ES256K (secp256k1), so importing such a key fails - treated like
					// Nimbus failing to build a verifier
					verifier = await JWKUtil.importKey(publicKey, verifierAlg);
				} else if (jwkKey["kty"] === "oct") {
					// MACVerifier: the secret must be at least 256 bits (KeyLengthException otherwise)
					if (Buffer.from(String(jwkKey["k"]), "base64url").length < 256 / 8) {
						throw new KeyLengthException("The secret length must be at least 256 bits");
					}
					verifier = await JWKUtil.importKey(jwkKey, alg);
				}
			} catch {
				// Java: catch (JOSEException | ParseException e) {} - the library could not build a verifier for this key
				// (TS: jose/WebCrypto import failures are not JOSEExceptions, so every failure lands here)
				verifier = null;
			}
			if (verifier != null) {
				if (verifierAlg !== alg) {
					// ECDSAVerifier.verify() throws for an algorithm that does not match the key's curve
					throw new JOSEException(unsupportedJWSAlgorithm(alg, [verifierAlg]));
				}
				if (await verifyWith(jwt, verifier)) {
					return true;
				} else {
					// failed to verify with this key, moving on
					// not a failure yet as it might pass a different key
				}
			}
		}
		// if we got here, it hasn't been verified on any key
		return false;
	}

	/** @throws JOSEException */
	protected async verifyHMACSignature(jwt: SignedJWT, sharedSecret: string): Promise<boolean> {
		const secret = Buffer.from(sharedSecret, "utf8");
		if (secret.length < 256 / 8) {
			throw new KeyLengthException("The secret length must be at least 256 bits");
		}
		const alg = jwt.header["alg"] as string;
		if (!JWS_FAMILY_HMAC_SHA.includes(alg)) {
			throw new JOSEException(unsupportedJWSAlgorithm(alg, JWS_FAMILY_HMAC_SHA));
		}
		return verifyWith(jwt, new Uint8Array(secret));
	}
}

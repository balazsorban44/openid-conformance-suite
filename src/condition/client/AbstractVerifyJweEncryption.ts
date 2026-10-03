import { AbstractCondition, args, type JsonObject } from "../../framework/index.ts";
import { JWE_FAMILY_ASYMMETRIC, JWKUtil, ParseException } from "../../util/JWKUtil.ts";
import { JWTUtil } from "../../util/JWTUtil.ts";
import { keyTypeForAlgorithm } from "../../util/nimbus/algorithms.ts";

export abstract class AbstractVerifyJweEncryption extends AbstractCondition {
	protected verifyJweEncryption(token: string, publicJwks: JsonObject, tokenName: string): boolean {
		try {
			// Translate the token into nimbus objects
			const jwt = JWTUtil.parseJWT(token);

			// We are only interested in encrypted JWTs.
			if (jwt.type === "encrypted") {
				const header = jwt.header;
				const headerKeyID = (header["kid"] as string | undefined) ?? null;
				const headerAlg = (header["alg"] as string | undefined) ?? null;

				if (headerAlg == null) {
					throw this.error("The JWE header does not contain alg. This is required.", args(tokenName, token));
				}

				const headerKty = keyTypeForAlgorithm(headerAlg);
				if (headerKty == null) {
					// UPSTREAM: KeyType.forAlgorithm returns null for an unknown algorithm and getValue() then throws a NullPointerException
					throw new TypeError(
						'Cannot invoke "com.nimbusds.jose.jwk.KeyType.getValue()" because the return value of "com.nimbusds.jose.jwk.KeyType.forAlgorithm(com.nimbusds.jose.Algorithm)" is null',
					);
				}

				// We are only interested in JWTs encrypted with an asymmetric algorithm
				if (JWE_FAMILY_ASYMMETRIC.includes(headerAlg)) {
					const jwkSet = JWKUtil.parseJWKSet(JSON.stringify(publicJwks));

					// Check for matches in the key set.
					let numberOfValidKeys = 0;
					let numberOfValidKeysWithKid = 0;

					for (const jwkKey of jwkSet.keys) {
						// Match on key type
						if (jwkKey["kty"] === headerKty) {
							numberOfValidKeys++;

							// If a kid was specified note a match.
							if (headerKeyID != null && headerKeyID === jwkKey["kid"]) {
								numberOfValidKeysWithKid++;
							}
						}
					}

					// Multiple keys matched, none matching the kid hint.
					if (headerKeyID != null && numberOfValidKeys > 1 && numberOfValidKeysWithKid === 0) {
						throw this.error(
							"Found multiple keys in JWKS of the correct type, but none with matching kid hint.",
							args("jwks", publicJwks, "kid", headerKeyID, "kty", headerKty, tokenName, token),
						);
					}

					// Multiple keys matched, including the kid hint.
					if (headerKeyID != null && numberOfValidKeysWithKid > 1) {
						throw this.error(
							"Found multiple keys in JWKS of the correct type and with the same kid hint.",
							args("jwks", publicJwks, "kid", headerKeyID, "kty", headerKty, tokenName, token),
						);
					}

					// Multiple keys matched, no kid hint.
					if (headerKeyID == null && numberOfValidKeys > 1) {
						throw this.error(
							"Found multiple keys in JWKS of the correct type but no kid hint in JWE header.",
							args("jwks", publicJwks, "kty", headerKty, tokenName, token),
						);
					}

					// Single key matched, kid hint does not match.
					if (headerKeyID != null && numberOfValidKeys === 1 && numberOfValidKeysWithKid === 0) {
						throw this.error(
							"Single key in JWKS of the correct type, but does not match kid hint.",
							args("jwks", publicJwks, "kid", headerKeyID, "kty", headerKty, tokenName, token),
						);
					}

					// The encryption has been verified.
					return true;
				}
			}

			// The encryption algorithm, if any, was not asymmetric.
			return false;
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error("Error validating " + tokenName + " encryption", e);
			}
			throw e;
		}
	}
}

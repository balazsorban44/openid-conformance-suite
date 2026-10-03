import {
	args,
	has,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";
import { JOSEException } from "../../util/JWEUtil.ts";
import { JWKUtil, ParseException, type JWK } from "../../util/JWKUtil.ts";
import { EC_CURVE_ALGORITHM } from "../../util/nimbus/algorithms.ts";
import { selectJWSJwks, verifySignedJWT, type JWSVerifier } from "../../util/nimbus/jws.ts";
import { parseSignedJWT } from "../../util/nimbus/jwt.ts";
import { AbstractLenientJwksCondition } from "../AbstractLenientJwksCondition.ts";

export class ValidateRequestObjectSignature extends AbstractLenientJwksCondition {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_request_object", "client_public_jwks", "client"],
	};
	static override post: EnvironmentRequirements = { strings: ["request_object_signing_alg"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const requestObject = env.getString("authorization_request_object", "value") as string;
		const clientJwks = env.getObject("client_public_jwks") as JsonObject;

		try {
			const jwt = parseSignedJWT(requestObject);
			// parse leniently: skip keys the JOSE library cannot handle (e.g. unsupported curves
			// like Brainpool, or future PQ algorithms) so an unusable key elsewhere in the client's
			// set does not abort verification when a usable signing key is present; skipped keys are logged
			const jwkSet = this.parseJwksLenientlyLoggingSkips(JSON.stringify(clientJwks), "client");

			const client = env.getObject("client") as JsonObject;
			if (has(client, "request_object_signing_alg")) {
				//https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
				//request_object_signing_alg
				//All Request Objects from this Client MUST be rejected, if not signed with this algorithm.
				//The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used
				const expectedAlg = OIDFJSON.getString(client["request_object_signing_alg"]);
				const jwsAlgorithm = jwt.header["alg"] as string;
				if (jwsAlgorithm !== expectedAlg) {
					throw this.error(
						"Algorithm in JWT header does not match client request_object_signing_alg.",
						args("actual", jwsAlgorithm, "expected", expectedAlg),
					);
				}
			}

			const jwkKeys = selectJWSJwks(jwt.header, jwkSet);
			if (jwkKeys == null || jwkKeys.length === 0) {
				throw this.error(
					"Could not find any keys that can be used to verify this signature",
					args("requestObject", requestObject, "clientJwks", clientJwks),
				);
			}

			const newJwkSet: JsonObject = { keys: jwkKeys };
			const publicJwks = JWKUtil.getPublicJwksAsJsonObject(newJwkSet);

			// Record why each candidate key did not verify the signature. Kept until the end and only
			// reported if NO key works, so a usable key verifying does not produce noise about the others.
			const failedKeys: JsonArray = [];

			const headerAlg = jwt.header["alg"] as string;
			for (const jwkKey of jwkKeys) {
				let verifier: JWSVerifier | null = null;
				try {
					if (jwkKey["kty"] === "OKP") {
						const publicKey = JWKUtil.toPublicJWK(jwkKey) as JWK;
						if ("Ed25519" === publicKey["crv"]) {
							verifier = {
								jwk: publicKey,
								key: await JWKUtil.importKey(publicKey, headerAlg === "Ed25519" ? "Ed25519" : "EdDSA"),
							};
						} else {
							this.recordFailedKey(
								failedKeys,
								jwkKey,
								"the JOSE library cannot verify with this key's curve ('" + String(publicKey["crv"]) + "')",
							);
						}
					} else if (jwkKey["kty"] === "RSA" || jwkKey["kty"] === "EC") {
						const publicKey = JWKUtil.toPublicJWK(jwkKey) as JWK;
						// like Nimbus' ECDSAVerifier, an EC key is bound to the algorithm of its curve; a mismatch with
						// the header alg is reported by verify()
						const keyAlg =
							publicKey["kty"] === "EC" ? (EC_CURVE_ALGORITHM[publicKey["crv"] as string] ?? headerAlg) : headerAlg;
						verifier = { jwk: publicKey, key: await JWKUtil.importKey(publicKey, keyAlg) };
					} else if (jwkKey["kty"] === "oct") {
						const secretKey = (await JWKUtil.importKey(jwkKey, headerAlg)) as Uint8Array;
						if (secretKey.length * 8 < 256) {
							throw new JOSEException("The secret length must be at least 256 bits");
						}
						verifier = { jwk: jwkKey, key: secretKey };
					}
				} catch (e) {
					// jose has no equivalent of some Nimbus verifiers (e.g. ES256K) and rejects some keys at import
					// time - both are reported like Nimbus failing to build a verifier
					this.recordFailedKey(
						failedKeys,
						jwkKey,
						"the JOSE library could not build a verifier for this key: " + (e as Error).message,
					);
				}
				if (verifier != null) {
					if (await verifySignedJWT(jwt, verifier)) {
						const alg = headerAlg;
						env.putString("request_object_signing_alg", alg);
						this.logSuccess(
							"Request object signature validated using a key in the client's JWKS " +
								"and using the client's registered request_object_signing_alg",
							args(
								"request_object_signing_alg",
								alg,
								"jwk",
								JSON.stringify(jwkKey),
								"keys",
								publicJwks,
								"request_object",
								requestObject,
							),
						);
						return env;
					} else {
						// failed to verify with this key, moving on - not a failure yet as it might pass a different key
						this.recordFailedKey(failedKeys, jwkKey, "the signature did not verify with this key");
					}
				}
			}

			// if we got here, it hasn't been verified by any key
			throw this.error(
				"Unable to verify request object signature based on client keys",
				args(
					"jwt_header",
					JSON.stringify(jwt.header),
					"keys",
					publicJwks,
					"failed_keys",
					failedKeys,
					"clientJwks",
					clientJwks,
					"requestObject",
					requestObject,
				),
			);
		} catch (e) {
			if (e instanceof JOSEException || e instanceof ParseException) {
				throw this.error("error validating request object signature", e);
			}
			throw e;
		}
	}

	private recordFailedKey(failedKeys: JsonArray, jwkKey: JWK, reason: string): void {
		const entry: JsonObject = {};
		entry["kid"] = (jwkKey["kid"] as string | undefined) ?? null;
		if (jwkKey["kty"] != null) {
			entry["kty"] = jwkKey["kty"] as string;
		}
		entry["reason"] = reason;
		failedKeys.push(entry);
	}
}

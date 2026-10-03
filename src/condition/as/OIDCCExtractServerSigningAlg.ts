import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import {
	JWKUtil,
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
	ParseException,
} from "../../util/JWKUtil.ts";
import { AbstractClientValidationCondition } from "./dynregistration/AbstractClientValidationCondition.ts";

export class OIDCCExtractServerSigningAlg extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["server_jwks", "client"] };
	static override post: EnvironmentRequirements = { strings: ["signing_algorithm"] };

	/**
	 * if client has id_token_signed_response_alg use that if we have a suitable key
	 * else use the alg for the first key in server_jwks, should default to RS256
	 *
	 * MUST be called after dynamic client registration when using dynamic client registration
	 * @param env
	 * @return
	 */
	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;
		const configuredAlg = env.getString("client", "id_token_signed_response_alg");
		if (configuredAlg == null) {
			return this.selectFirstSigningKeyFromServerJwks(env);
		} else {
			if ("none" === configuredAlg) {
				if (this.hasImplicitResponseTypes()) {
					throw this.error("none algorithm can only be used when only 'code' response type will be used");
				}
				env.putString("signing_algorithm", "none");
				this.logSuccess(
					"Using client id_token_signed_response_alg, which is 'none', as the signing algorithm",
					args("signing_algorithm", configuredAlg),
				);
				return env;
			}
			const configuredJwsAlgorithm = configuredAlg;
			if (configuredAlg.startsWith("HS")) {
				if (!JWS_FAMILY_HMAC_SHA.includes(configuredJwsAlgorithm)) {
					throw this.error("Unexpected algorithm", args("alg", configuredAlg));
				}
				env.putString("signing_algorithm", configuredAlg);
				this.logSuccess(
					"Using client id_token_signed_response_alg as the signing algorithm",
					args("signing_algorithm", configuredAlg),
				);
				return env;
			} else {
				const jwks = env.getObject("server_jwks") as JsonObject;
				return this.selectKeyFromServerJwksForAlgorithm(env, jwks, configuredJwsAlgorithm);
			}
		}
	}

	private selectKeyFromServerJwksForAlgorithm(
		env: Environment,
		jwks: JsonObject,
		configuredJwsAlgorithm: string,
	): Environment {
		try {
			const jwkSet = JWKUtil.parseJWKSet(JSON.stringify(jwks));
			let keyType: string | null = null;
			if (JWS_FAMILY_RSA.includes(configuredJwsAlgorithm)) {
				keyType = "RSA";
			} else if (JWS_FAMILY_EC.includes(configuredJwsAlgorithm)) {
				keyType = "EC";
			} else if (JWS_FAMILY_ED.includes(configuredJwsAlgorithm)) {
				keyType = "OKP";
			}
			let foundAlg: string | null = null;

			if (jwkSet != null) {
				const keys = jwkSet.keys;
				for (const key of keys) {
					if (key["kty"] === keyType) {
						if (key["use"] == null || "sig" === key["use"]) {
							if (key["alg"] == null) {
								//there may be a more specific match later so don't break
								foundAlg = configuredJwsAlgorithm;
							} else if (key["alg"] === configuredJwsAlgorithm) {
								//best match, this is it
								foundAlg = configuredJwsAlgorithm;
								break;
							}
						}
					}
				}
			}
			if (foundAlg == null) {
				throw this.error(
					"Could not find a suitable key in server_jwks for client id_token_signed_response_alg.",
					args("server_jwks", jwks, "id_token_signed_response_alg", configuredJwsAlgorithm),
				);
			}
			env.putString("signing_algorithm", foundAlg);
			this.logSuccess(
				"Selected signing algorithm based on client id_token_signed_response_alg.",
				args("selected_algorithm", foundAlg, "id_token_signed_response_alg", configuredJwsAlgorithm),
			);
			return env;
		} catch (e) {
			if (!(e instanceof ParseException)) {
				throw e;
			}
			throw this.error("Could not parse server jwks.", e, args("server_jwks", jwks));
		}
	}

	/**
	 * these are the default algorithms based on key type
	 * @param keyType
	 * @return
	 */
	protected getDefaultAlgForKeyType(keyType: string): string {
		if ("RSA" === keyType) {
			return "RS256";
		} else if ("EC" === keyType) {
			return "ES256";
		} else if ("OKP" === keyType) {
			return "EdDSA";
		} else if ("oct" === keyType) {
			return "HS256";
		} else {
			throw this.error("Unexpected key type", args("key_type", keyType));
		}
	}

	/**
	 * use the alg from the first signing key in server jwks
	 * if the first key has no alg then use RS256, ES256 or EdDSA based on key type
	 * @param env
	 * @return
	 */
	private selectFirstSigningKeyFromServerJwks(env: Environment): Environment {
		const jwks = env.getObject("server_jwks") as JsonObject;
		try {
			const jwkSet = JWKUtil.parseJWKSet(JSON.stringify(jwks));
			for (const jwk of jwkSet.keys) {
				if (jwk["use"] != null && "sig" !== jwk["use"]) {
					continue;
				}
				let alg = jwk["alg"] as string | undefined;
				if (alg == null) {
					alg = this.getDefaultAlgForKeyType(jwk["kty"] as string);
					env.putString("signing_algorithm", alg);
					this.logSuccess(
						"Using the default algorithm for the first key in server jwks",
						args("signing_algorithm", alg),
					);
					return env;
				} else {
					env.putString("signing_algorithm", alg);
					this.logSuccess("Using the algorithm for the first key in server jwks", args("signing_algorithm", alg));
					return env;
				}
			}
			throw this.error("Failed to find a suitable signing key in server jwks", args("server_jwks", jwks));
		} catch (e) {
			if (!(e instanceof ParseException)) {
				throw e;
			}
			throw this.error("Failed to parse server_jwks", e, args("server_jwks", jwks));
		}
	}
}

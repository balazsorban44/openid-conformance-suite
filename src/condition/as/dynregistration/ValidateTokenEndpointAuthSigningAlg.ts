import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { JWS_FAMILY_EC, JWS_FAMILY_ED, JWS_FAMILY_HMAC_SHA, JWS_FAMILY_RSA } from "../../../util/JWKUtil.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 *  token_endpoint_auth_signing_alg
 *  OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing the JWT [JWT]
 *  used to authenticate the Client at the Token Endpoint for the private_key_jwt and
 *  client_secret_jwt authentication methods. All Token Requests using these authentication
 *  methods from this Client MUST be rejected, if the JWT is not signed with this algorithm.
 *  Servers SHOULD support RS256. The value none MUST NOT be used. The default, if omitted,
 *  is that any algorithm supported by the OP and the RP MAY be used.
 *
 */
export class ValidateTokenEndpointAuthSigningAlg extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;

		const alg = this.getTokenEndpointAuthSigningAlg();
		if (alg == null) {
			this.logSuccess("token_endpoint_auth_signing_alg is not set");
			return env;
		}
		if ("none" === alg) {
			throw this.error("'none' cannot be used for client authentication");
		}

		const clientAuthType = this.getTokenEndpointAuthMethod();
		if ("client_secret_jwt" === clientAuthType) {
			const jwsAlgorithm = alg;
			if (!JWS_FAMILY_HMAC_SHA.includes(jwsAlgorithm)) {
				throw this.error("Invalid algorithm for client_secret_jwt", args("alg", alg));
			}
			this.logSuccess("token_endpoint_auth_signing_alg is valid", args("token_endpoint_auth_signing_alg", alg));
			return env;
		}
		if ("private_key_jwt" === clientAuthType) {
			const jwsAlgorithm = alg;
			if (
				JWS_FAMILY_EC.includes(jwsAlgorithm) ||
				JWS_FAMILY_ED.includes(jwsAlgorithm) ||
				JWS_FAMILY_RSA.includes(jwsAlgorithm)
			) {
				this.logSuccess("token_endpoint_auth_signing_alg is valid", args("token_endpoint_auth_signing_alg", alg));
				return env;
			} else {
				throw this.error("Invalid algorithm for private_key_jwt", args("token_endpoint_auth_signing_alg", alg));
			}
		}
		this.logSuccess(
			"token_endpoint_auth_signing_alg is set but it is not applicable to client authentication method",
			args("token_endpoint_auth_signing_alg", alg, "token_endpoint_auth_method", clientAuthType),
		);
		return env;
	}
}

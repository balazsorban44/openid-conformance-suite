import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { JWSUtil } from "../../../util/JWSUtil.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 *  id_token_signed_response_alg
 *   OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client.
 *   The value none MUST NOT be used as the ID Token alg value unless the Client uses only
 *   Response Types that return no ID Token from the Authorization Endpoint
 *   (such as when only using the Authorization Code Flow). The default, if omitted, is RS256.
 *   The public key for validating the signature is provided by retrieving the JWK Set referenced
 *   by the jwks_uri element from OpenID Connect Discovery 1.0 [OpenID.Discovery].
 *
 *   Please note: This condition does not validate if the current test actually supports the alg,
 *   it will fail later anyway
 */
export class ValidateIdTokenSignedResponseAlg extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;

		const alg = this.getIdTokenSignedResponseAlg();
		if ("none" === alg) {
			if (this.hasImplicitResponseTypes()) {
				throw this.error("none algorithm can only be used if only 'code' response type will be used");
			} else {
				this.logSuccess("none algorithm is allowed as only 'code' response type will be used");
				return env;
			}
		}

		if (JWSUtil.isValidJWSAlgorithm(alg)) {
			this.logSuccess("id_token_signed_response_alg is one of the known algorithms", args("alg", alg));
			return env;
		}
		throw this.error("Unexpected id_token_signed_response_alg", args("alg", alg));
	}
}

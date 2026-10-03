import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { JWSUtil } from "../../../util/JWSUtil.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 *  userinfo_signed_response_alg
 *  OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified,
 *  the response will be JWT [JWT] serialized, and signed using JWS. The default, if omitted,
 *  is for the UserInfo Response to return the Claims as a UTF-8 encoded JSON object using the
 *  application/json content-type.
 *
 *   Please note: This condition does not validate if the current test actually supports the alg,
 *   it will fail later anyway
 */
export class ValidateUserinfoSignedResponseAlg extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;

		const alg = this.getUserinfoSignedResponseAlg();

		if (JWSUtil.isValidJWSAlgorithm(alg)) {
			this.logSuccess("userinfo_signed_response_alg is one of the known algorithms", args("alg", alg));
			return env;
		}
		throw this.error("Unexpected userinfo_signed_response_alg", args("alg", alg));
	}
}

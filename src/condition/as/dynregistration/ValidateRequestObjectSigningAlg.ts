import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { JWSUtil } from "../../../util/JWSUtil.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 *  request_object_signing_alg
 *  OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects
 *  sent to the OP. All Request Objects from this Client MUST be rejected, if not signed
 *  with this algorithm. Request Objects are described in Section 6.1 of OpenID Connect
 *  Core 1.0 [OpenID.Core]. This algorithm MUST be used both when the Request Object is
 *  passed by value (using the request parameter) and when it is passed by reference
 *  (using the request_uri parameter). Servers SHOULD support RS256. The value none MAY
 *  be used. The default, if omitted, is that any algorithm supported by the OP and the
 *  RP MAY be used.
 *
 *   Please note: This condition does not validate if the current test actually supports the alg,
 *   it will fail later anyway
 */
export class ValidateRequestObjectSigningAlg extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;

		const alg = this.getRequestObjectSigningAlg();
		if (alg == null) {
			this.logSuccess("request_object_signing_alg is not set");
			return env;
		}
		if ("none" === alg) {
			this.logSuccess("request_object_signing_alg is 'none'");
			return env;
		}

		if (JWSUtil.isValidJWSAlgorithm(alg)) {
			this.logSuccess("request_object_signing_alg is one of the known algorithms", args("alg", alg));
			return env;
		}
		throw this.error("Unexpected request_object_signing_alg", args("alg", alg));
	}
}

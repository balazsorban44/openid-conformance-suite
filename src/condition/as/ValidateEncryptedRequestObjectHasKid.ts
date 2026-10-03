import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { JWEUtil } from "../../util/JWEUtil.ts";

export class ValidateEncryptedRequestObjectHasKid extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_request_object"] };

	override evaluate(env: Environment): Environment {
		const alg = env.getString("authorization_request_object", "jwe_header.alg");

		if (JWEUtil.isSymmetricJWEAlgorithm(alg)) {
			this.logSuccess("skipping KID check for symmetric alg " + alg);
		} else {
			const kid = env.getString("authorization_request_object", "jwe_header.kid");
			if (!kid) {
				throw this.error("kid was not found in the encrypted request object header");
			}
			this.logSuccess("kid was found in the encrypted request object header", args("kid", kid));
		}

		return env;
	}
}

import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { JWEUtil } from "../../util/JWEUtil.ts";

export class ValidateEncryptedIdTokenHasKid extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token"] };

	override evaluate(env: Environment): Environment {
		const alg = env.getString("id_token", "jwe_header.alg");
		const kid = env.getString("id_token", "jwe_header.kid");
		if (JWEUtil.isSymmetricJWEAlgorithm(alg as string)) {
			this.logSuccess("skipping KID check for symmetric alg " + alg);
		} else {
			if (!kid) {
				throw this.error("kid was not found in the encrypted ID token header");
			}
			this.logSuccess("kid was found in the encrypted ID token header", args("kid", kid));
		}

		return env;
	}
}

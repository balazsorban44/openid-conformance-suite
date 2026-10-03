import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureRequestObjectWasSignedWithRS256 extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_request_object"] };

	override evaluate(env: Environment): Environment {
		const alg = env.getString("authorization_request_object", "header.alg");

		if ("RS256" === alg) {
			this.logSuccess("Request object was signed using RS256 algorithm");
			return env;
		}
		throw this.error("Request object must be signed with RS256", args("actual", alg));
	}
}

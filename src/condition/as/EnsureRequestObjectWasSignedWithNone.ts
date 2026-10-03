import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureRequestObjectWasSignedWithNone extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_request_object"] };

	override evaluate(env: Environment): Environment {
		const alg = env.getString("authorization_request_object", "header.alg");

		if ("none" === alg) {
			this.logSuccess("Request object was signed using algorithm 'none'");
			return env;
		}
		throw this.error("Request object must be signed with algorithm 'none'", args("actual", alg));
	}
}

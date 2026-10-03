import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureIdTokenContainsKid extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token"] };

	override evaluate(env: Environment): Environment {
		const kid = env.getString("id_token", "header.kid");

		if (!kid) {
			throw this.error("kid was not found in the ID token header");
		}

		this.logSuccess("kid was found in the ID token header", args("kid", kid));

		return env;
	}
}

import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureIdTokenContainsName extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token"] };

	override evaluate(env: Environment): Environment {
		const name = env.getString("id_token", "claims.name");

		if (!name) {
			throw this.error("name not found in id_token");
		}

		this.logSuccess("Found name in id_token", args("name", name));

		return env;
	}
}

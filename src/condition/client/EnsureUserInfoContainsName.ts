import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureUserInfoContainsName extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["userinfo"] };

	override evaluate(env: Environment): Environment {
		const name = env.getString("userinfo", "name");

		if (!name) {
			throw this.error("name not found in userinfo");
		}

		this.logSuccess("Found name in userinfo", args("name", name));

		return env;
	}
}

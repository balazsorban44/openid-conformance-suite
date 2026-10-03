import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureUserInfoContainsSub extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["userinfo"] };

	override evaluate(env: Environment): Environment {
		const sub = env.getString("userinfo", "sub");

		if (!sub) {
			throw this.error("sub not found in userinfo");
		}

		this.logSuccess("Found sub in userinfo", args("sub", sub));

		return env;
	}
}

import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class RequireBearerAccessToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["incoming_access_token"] };

	override evaluate(env: Environment): Environment {
		const actual = env.getString("incoming_access_token");
		const expected = env.getString("access_token");

		if (expected == null) {
			throw this.error(
				"This endpoint must be called with an access token, but a suitable access token has not been created in this run of the test.",
			);
		}

		if (actual && actual === expected) {
			this.logSuccess("Found access token in request", args("actual", actual ?? ""));
			return env;
		} else {
			throw this.error("Invalid access token ", args("expected", expected ?? "", "actual", actual ?? ""));
		}
	}
}

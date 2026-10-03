import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckForRefreshTokenValue extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		if (env.getString("token_endpoint_response", "refresh_token")) {
			this.logSuccess(
				"Found a refresh token",
				args("refresh_token", env.getString("token_endpoint_response", "refresh_token")),
			);
			return env;
		} else {
			throw this.error("Couldn't find refresh token");
		}
	}
}

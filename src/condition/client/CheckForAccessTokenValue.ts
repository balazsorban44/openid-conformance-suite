import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckForAccessTokenValue extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		if (!env.getString("token_endpoint_response", "access_token")) {
			throw this.error("access_token is missing or empty in token endpoint response");
		}
		if (!env.getString("token_endpoint_response", "token_type")) {
			throw this.error("token_type is missing or empty in token endpoint response");
		}

		this.logSuccess(
			"Found an access token",
			args("access_token", env.getString("token_endpoint_response", "access_token")),
		);
		return env;
	}
}

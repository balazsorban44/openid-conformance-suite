import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExtractRefreshTokenFromTokenResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };
	static override post: EnvironmentRequirements = { strings: ["refresh_token"] };

	override evaluate(env: Environment): Environment {
		const refreshToken = env.getString("token_endpoint_response", "refresh_token");
		if (refreshToken == null) {
			// It's perfectly legal to NOT return a new refresh token; if the server didn't then
			// 'refresh_token' in the environment will be left containing the old (still valid)
			// token. We use that token later to test the refresh token is bound to the client
			// correctly.
			throw this.error("Token endpoint response does not contain a refresh token");
		}
		env.putString("refresh_token", refreshToken);
		this.logSuccess("Extracted refresh token from response", args("refresh_token", refreshToken));
		return env;
	}
}

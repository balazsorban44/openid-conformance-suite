import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExtractInitialAccessTokenFromStoredConfig extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["original_client_config"] };

	override evaluate(env: Environment): Environment {
		env.removeNativeValue("initial_access_token");

		// pull out any initial access token and put it in the root environment for easy access (if there is one)
		const initialAccessToken = env.getString("original_client_config", "initial_access_token");
		if (initialAccessToken) {
			env.putString("initial_access_token", initialAccessToken);
		}
		this.log(
			"Extracted initial access_token from stored client configuration.",
			args("initial_access_token", initialAccessToken || null),
		);

		return env;
	}
}

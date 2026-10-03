import {
	AbstractCondition,
	args,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class GenerateBearerAccessToken extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["access_token", "token_type"] };

	override evaluate(env: Environment): Environment {
		const accessToken = RandomStringUtils.nextAlphanumeric(50);

		this.logSuccess("Generated access token", args("access_token", accessToken));

		env.putString("access_token", accessToken);
		env.putString("token_type", "Bearer");

		return env;
	}
}

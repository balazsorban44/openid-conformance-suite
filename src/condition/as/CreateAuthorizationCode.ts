import {
	AbstractCondition,
	args,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class CreateAuthorizationCode extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["authorization_code"] };

	override evaluate(env: Environment): Environment {
		const code = RandomStringUtils.nextAlphanumeric(32);

		env.putString("authorization_code", code);

		this.logSuccess("Created authorization code", args("authorization_code", code));

		return env;
	}
}

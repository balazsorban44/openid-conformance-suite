import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureAccessTokenValuesAreDifferent extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["first_access_token", "second_access_token"] };

	override evaluate(env: Environment): Environment {
		const firstAccessToken = env.getString("first_access_token", "value");
		const secondAccessToken = env.getString("second_access_token", "value");

		if (firstAccessToken == null) {
			throw this.error("first_access_token is null");
		}

		if (secondAccessToken == null) {
			throw this.error("second_access_token is null");
		}

		if (firstAccessToken === secondAccessToken) {
			throw this.error("Access token values are not different");
		}

		this.logSuccess(
			"Access token values are not the same",
			args("first_access_token", firstAccessToken, "second_access_token", secondAccessToken),
		);

		return env;
	}
}

import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class RejectAuthCodeInAuthorizationEndpointResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["callback_query_params", "callback_params"] };

	override evaluate(env: Environment): Environment {
		if (env.getString("callback_query_params", "code") != null) {
			throw this.error("Authorization code is present in URL query but an error was expected");
		}

		if (env.getString("callback_params", "code") != null) {
			throw this.error("Authorization code is present in URL fragment returned from but an error was expected");
		}

		this.logSuccess("Authorization code is not present in authorization endpoint response");
		return env;
	}
}

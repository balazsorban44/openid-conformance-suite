import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class EnsureMatchingClientId extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["client", CreateEffectiveAuthorizationRequestParameters.ENV_KEY],
	};

	override evaluate(env: Environment): Environment {
		// get the client ID from the configuration
		const expected = env.getString("client", "client_id");
		const actual = env.getString(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.CLIENT_ID,
		);

		if (expected && expected === actual) {
			this.logSuccess("Client ID matched", args("client_id", actual ?? ""));
			return env;
		} else {
			throw this.error(
				"Mismatch between Client ID in test configuration and the one in the authorization request",
				args("expected", expected ?? "", "actual", actual ?? ""),
			);
		}
	}
}

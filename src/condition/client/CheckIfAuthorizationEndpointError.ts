import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Check if there was an error from the authorization endpoint. If so, log the error and quit. If not, pass.
 */
export class CheckIfAuthorizationEndpointError extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		if (env.getString("authorization_endpoint_response", "error")) {
			throw this.error(
				"The authorization was expected to succeed, but the server returned an error from the authorization endpoint",
				env.getObject("authorization_endpoint_response") as JsonObject,
			);
		}

		this.logSuccess("No error from authorization endpoint");
		return env;
	}
}

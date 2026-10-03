import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CheckIfTokenEndpointResponseError extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		if (!env.containsObject("token_endpoint_response")) {
			throw this.error("Couldn't find token endpoint response");
		}

		if (env.getString("token_endpoint_response", "error")) {
			throw this.error(
				"The token endpoint call was expected to succeed, but it returned an error response",
				env.getObject("token_endpoint_response") as JsonObject,
			);
		} else {
			this.logSuccess("No error from token endpoint");
			return env;
		}
	}
}

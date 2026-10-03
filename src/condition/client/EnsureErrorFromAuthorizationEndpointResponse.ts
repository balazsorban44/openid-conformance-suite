import {
	AbstractCondition,
	has,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class EnsureErrorFromAuthorizationEndpointResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const callbackParams = env.getObject("authorization_endpoint_response") as JsonObject;

		if (!has(callbackParams, "error")) {
			throw this.error("Authorization server was expected to return an error but did not", callbackParams);
		}

		this.logSuccess("Authorization endpoint returned an error", callbackParams);

		return env;
	}
}

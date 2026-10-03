import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddStateToAuthorizationEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"], strings: ["state"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const state = env.getString("state");
		if (!state) {
			throw this.error("Couldn't find state value");
		}

		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		authorizationEndpointRequest["state"] = state;

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess("Added state parameter to request", authorizationEndpointRequest);

		return env;
	}
}

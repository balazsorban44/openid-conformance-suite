import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class SetAuthorizationEndpointRequestResponseTypeFromEnvironment extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_endpoint_request"],
		strings: ["response_type"],
	};
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const responseType = env.getString("response_type");
		if (!responseType) {
			throw this.error("No response_type found in config");
		}

		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		authorizationEndpointRequest["response_type"] = responseType;

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess("Added response_type parameter to request", authorizationEndpointRequest);

		return env;
	}
}

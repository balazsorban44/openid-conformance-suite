import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddMaxAge15000ToAuthorizationEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const value = 15000;

		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		authorizationEndpointRequest["max_age"] = value;

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess("Added max_age=" + value + " to authorization endpoint request", authorizationEndpointRequest);

		return env;
	}
}

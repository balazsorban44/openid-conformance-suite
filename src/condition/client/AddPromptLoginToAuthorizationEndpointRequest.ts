import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddPromptLoginToAuthorizationEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		authorizationEndpointRequest["prompt"] = "login";

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess("Added prompt=login to authorization endpoint request", authorizationEndpointRequest);

		return env;
	}
}

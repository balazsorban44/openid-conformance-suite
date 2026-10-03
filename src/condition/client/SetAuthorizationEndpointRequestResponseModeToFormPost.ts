import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class SetAuthorizationEndpointRequestResponseModeToFormPost extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		authorizationEndpointRequest["response_mode"] = "form_post";

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.log("Added response_mode parameter to request", authorizationEndpointRequest);

		return env;
	}
}

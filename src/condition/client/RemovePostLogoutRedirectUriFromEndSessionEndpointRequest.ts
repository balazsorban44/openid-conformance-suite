import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class RemovePostLogoutRedirectUriFromEndSessionEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["end_session_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["end_session_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const endSessionEndpointRequest = env.getObject("end_session_endpoint_request") as JsonObject;

		delete endSessionEndpointRequest["post_logout_redirect_uri"];

		env.putObject("end_session_endpoint_request", endSessionEndpointRequest);

		this.logSuccess("Removed post_logout_redirect_uri from end session endpoint request", endSessionEndpointRequest);

		return env;
	}
}

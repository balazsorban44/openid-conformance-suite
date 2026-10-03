import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class CreatePostLogoutRedirectUriParams extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["end_session_endpoint_http_request_params"] };
	static override post: EnvironmentRequirements = { required: ["post_logout_redirect_uri_params"] };

	override evaluate(env: Environment): Environment {
		const state = env.getString("end_session_endpoint_http_request_params", "state");

		const responseParams: JsonObject = {};
		if (state != null) {
			responseParams["state"] = state;
		}

		this.log("Added post_logout_redirect_uri parameters to environment", args("params", responseParams));

		env.putObject("post_logout_redirect_uri_params", responseParams);

		return env;
	}
}

import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateEndSessionEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token"], strings: ["post_logout_redirect_uri"] };
	static override post: EnvironmentRequirements = { required: ["end_session_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const idToken = env.getString("id_token", "value");
		if (!idToken) {
			throw this.error("Couldn't find id_token");
		}

		const postLogoutRedirectUri = env.getString("post_logout_redirect_uri");
		if (!postLogoutRedirectUri) {
			throw this.error("Couldn't find post_logout_redirect_uri");
		}

		const state = env.getString("end_session_state");
		// UPSTREAM: checks postLogoutRedirectUri instead of state, so a missing end_session_state is never detected
		if (!postLogoutRedirectUri) {
			throw this.error("Couldn't find end_session_state");
		}

		const endSessionEndpointRequest: JsonObject = {};
		endSessionEndpointRequest["id_token_hint"] = idToken;
		endSessionEndpointRequest["post_logout_redirect_uri"] = postLogoutRedirectUri;
		endSessionEndpointRequest["state"] = state;

		env.putObject("end_session_endpoint_request", endSessionEndpointRequest);

		this.logSuccess("Created end session endpoint request", endSessionEndpointRequest);

		return env;
	}
}

import {
	AbstractCondition,
	args,
	jsonArrayContains,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../../framework/index.ts";

export class ValidatePostLogoutRedirectUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["end_session_endpoint_http_request_params", "client"],
	};
	static override post: EnvironmentRequirements = {};

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;
		if (!("post_logout_redirect_uris" in client)) {
			throw this.error("The client does not have any post_logout_redirect_uris");
		}
		const registeredUris = client["post_logout_redirect_uris"] as JsonArray;
		const postLogoutRedirectUri = env.getString("end_session_endpoint_http_request_params", "post_logout_redirect_uri");
		if (postLogoutRedirectUri == null) {
			throw this.error("no post_logout_redirect_uri passed to end_session_endpoint");
		}
		const jsonElementForUri = postLogoutRedirectUri;
		if (!jsonArrayContains(registeredUris, jsonElementForUri)) {
			throw this.error(
				"Invalid post_logout_redirect_uri in request",
				args("registered_uris", registeredUris, "actual", jsonElementForUri),
			);
		}
		this.logSuccess(
			"post_logout_redirect_uri is one of the registered post_logout_redirect_uris",
			args("post_logout_redirect_uri", jsonElementForUri),
		);
		return env;
	}
}

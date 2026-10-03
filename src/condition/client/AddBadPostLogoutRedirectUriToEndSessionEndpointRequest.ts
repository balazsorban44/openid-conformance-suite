import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddBadPostLogoutRedirectUriToEndSessionEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["end_session_endpoint_request"], strings: ["base_url"] };
	static override post: EnvironmentRequirements = { required: ["end_session_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		let baseUrl = env.getString("base_url") as string;

		// Note that this url shouldn't be called, but for consistency allow it to be overridden just in case the OP calls it
		const externalUrlOverride = env.getString("external_url_override");
		if (externalUrlOverride) {
			baseUrl = externalUrlOverride;
		}

		// calculate the redirect URI based on our given base URL
		const postLogoutUri = baseUrl + "/bad_post_logout_redirect_uri";

		const endSessionEndpointRequest = env.getObject("end_session_endpoint_request") as JsonObject;

		endSessionEndpointRequest["post_logout_redirect_uri"] = postLogoutUri;

		env.putObject("end_session_endpoint_request", endSessionEndpointRequest);

		this.logSuccess("Added bad post_logout_redirect_uri to end session endpoint request", endSessionEndpointRequest);

		return env;
	}
}

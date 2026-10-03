import {
	AbstractCondition,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddPostLogoutRedirectUriWithQueryAddedToEndSessionEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["end_session_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["end_session_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const endSessionEndpointRequest = env.getObject("end_session_endpoint_request") as JsonObject;

		let postLogoutUri = OIDFJSON.getString(endSessionEndpointRequest["post_logout_redirect_uri"]);

		postLogoutUri += "?foo=bar";

		endSessionEndpointRequest["post_logout_redirect_uri"] = postLogoutUri;

		env.putObject("end_session_endpoint_request", endSessionEndpointRequest);

		this.logSuccess(
			"Added ?foo=bar to post_logout_redirect_uri in end session endpoint request",
			endSessionEndpointRequest,
		);

		return env;
	}
}

import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractBuildRequestObjectRedirectToAuthorizationEndpoint } from "./AbstractBuildRequestObjectRedirectToAuthorizationEndpoint.ts";

export class BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint extends AbstractBuildRequestObjectRedirectToAuthorizationEndpoint {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_endpoint_request", "request_object_claims", "server"],
		strings: ["request_uri"],
	};
	static override post: EnvironmentRequirements = { strings: ["redirect_to_authorization_endpoint"] };

	override evaluate(env: Environment): Environment {
		const requestUri = env.getString("request_uri");

		return this.buildRedirect(env, "request_uri", requestUri, true, false);
	}
}

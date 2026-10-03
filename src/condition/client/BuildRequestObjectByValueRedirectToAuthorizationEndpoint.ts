import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractBuildRequestObjectRedirectToAuthorizationEndpoint } from "./AbstractBuildRequestObjectRedirectToAuthorizationEndpoint.ts";

export class BuildRequestObjectByValueRedirectToAuthorizationEndpoint extends AbstractBuildRequestObjectRedirectToAuthorizationEndpoint {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_endpoint_request", "request_object_claims", "server"],
		strings: ["request_object"],
	};
	static override post: EnvironmentRequirements = { strings: ["redirect_to_authorization_endpoint"] };

	override evaluate(env: Environment): Environment {
		const requestObject = env.getString("request_object");

		return this.buildRedirect(env, "request", requestObject, true, false);
	}
}

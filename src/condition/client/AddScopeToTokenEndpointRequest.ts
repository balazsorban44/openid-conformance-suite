import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { ExtractGrantedScopeFromTokenEndpointResponse } from "./ExtractGrantedScopeFromTokenEndpointResponse.ts";

export class AddScopeToTokenEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_request_form_parameters", "client"] };
	static override post: EnvironmentRequirements = { required: ["token_endpoint_request_form_parameters"] };

	override evaluate(env: Environment): Environment {
		const tokenEndpointRequest = env.getObject("token_endpoint_request_form_parameters") as JsonObject;

		// RFC6749-6: a refresh request must not ask for anything beyond what was granted, so where the
		// granted scope is known (recorded by ExtractGrantedScopeFromTokenEndpointResponse) it takes
		// precedence over the scope configured for the client
		const grantedScope = env.getString("client", ExtractGrantedScopeFromTokenEndpointResponse.GRANTED_SCOPE);
		let scope = grantedScope;
		let source = "granted by the authorization server";

		if (!scope) {
			scope = env.getString("client", "scope");
			source = "configured for the client";
		}

		if (!scope) {
			throw this.error("scope missing/empty in client object");
		}

		tokenEndpointRequest["scope"] = scope;

		env.putObject("token_endpoint_request_form_parameters", tokenEndpointRequest);

		this.logSuccess("Added scope of '" + scope + "' (" + source + ") to token endpoint request", tokenEndpointRequest);

		return env;
	}
}

import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Records the scope the authorization server actually granted, as returned in the token endpoint response.
 *
 * RFC6749-6 requires that the scope of a refresh request "MUST NOT include any scope not originally granted
 * by the resource owner", so a subsequent refresh has to be based on the granted scope rather than on the
 * scope configured for the client - the two differ whenever the user, or a grant management action, narrows
 * what was granted. {@link AddScopeToTokenEndpointRequest} picks the value up from here.
 *
 * The value is stored under the client object, which the multiple-client tests map per client, so one
 * client cannot pick up the scope granted to another. It is also cleared when the response carries no
 * scope, so a stale value cannot survive into a later request by the same client.
 */
export class ExtractGrantedScopeFromTokenEndpointResponse extends AbstractCondition {
	static readonly GRANTED_SCOPE = "granted_scope";

	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response", "client"] };
	static override post: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;
		const grantedScope = env.getString("token_endpoint_response", "scope");

		if (!grantedScope) {
			delete client[ExtractGrantedScopeFromTokenEndpointResponse.GRANTED_SCOPE];
			this.logSuccess(
				"The token endpoint response does not contain a scope, so the requested scope will continue to be used",
			);
			return env;
		}

		client[ExtractGrantedScopeFromTokenEndpointResponse.GRANTED_SCOPE] = grantedScope;
		this.logSuccess("Recorded the scope granted by the authorization server", args("scope", grantedScope));

		return env;
	}
}

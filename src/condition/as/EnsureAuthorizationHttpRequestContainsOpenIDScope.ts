import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

/**
 * OIDCC 6.1 says:
 * Even if a scope parameter is present in the Request Object value, a scope parameter
 * MUST always be passed using the OAuth 2.0 request syntax containing the openid scope
 * value to indicate to the underlying OAuth 2.0 logic that this is an OpenID Connect request.
 */
export class EnsureAuthorizationHttpRequestContainsOpenIDScope extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_http_request_params"] };

	override evaluate(env: Environment): Environment {
		const scopeFromHttpRequest = env.getString("authorization_endpoint_http_request_params", "scope");

		if (!scopeFromHttpRequest) {
			throw this.error(
				"Http request parameters don't contain a scope parameter",
				args("request_parameters", env.getObject("authorization_endpoint_http_request_params")),
			);
		}
		const scopes = scopeFromHttpRequest.split(" ");

		if (scopes.includes("openid")) {
			this.logSuccess("Found 'openid' in scope http request parameter", args("expected", "openid", "actual", scopes));
			return env;
		} else {
			throw this.error(
				"Could not find 'openid' in scope http request parameter",
				args("expected", "openid", "actual", scopes),
			);
		}
	}
}

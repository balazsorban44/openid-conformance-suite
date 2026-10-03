import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

/**
 * compares the redirect_uri in token request with authorization_endpoint_request_redirect_uri
 */
export class ValidateRedirectUriForTokenEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["token_endpoint_request"],
		strings: ["authorization_endpoint_request_redirect_uri"],
	};

	override evaluate(env: Environment): Environment {
		const actual = env.getString("token_endpoint_request", "body_form_params.redirect_uri");
		const expected = env.getString("authorization_endpoint_request_redirect_uri");

		if (!actual) {
			/*
			TODO: should we allow no redirect_uri case when there is only one registered redirect_uri
			OIDC 3.1.3.2 says:
			 If the redirect_uri parameter value is not present when there is only one registered redirect_uri value,
			 the Authorization Server MAY return an error (since the Client should have included the parameter) or
			 MAY proceed without an error (since OAuth 2.0 permits the parameter to be omitted in this case).
			*/
			throw this.error(
				"redirect_uri is missing or empty",
				args("token_endpoint_request", env.getObject("token_endpoint_request")),
			);
		}

		if (actual === expected) {
			this.logSuccess("redirect_uri is the same as the one used in the authorization request", args("actual", actual));
			return env;
		}

		throw this.error(
			"redirect_uri is not equal to the one used in the authorization request",
			args("actual", actual, "expected", expected),
		);
	}
}

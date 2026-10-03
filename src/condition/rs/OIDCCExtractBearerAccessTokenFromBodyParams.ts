import {
	AbstractCondition,
	args,
	isJsonPrimitive,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

/**
 * Extract access token from body parameters
 * but don't allow more than access_token values or more than one method (header + body etc)
 * and don't allow access_token in query string
 */
export class OIDCCExtractBearerAccessTokenFromBodyParams extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["incoming_request"] };
	static override post: EnvironmentRequirements = { strings: ["incoming_access_token"] };

	override evaluate(env: Environment): Environment {
		const authHeader = env.getString("incoming_request", "headers.authorization");
		if (authHeader) {
			if (authHeader.toLowerCase().startsWith("bearer ")) {
				const tokenFromHeader = authHeader.substring("bearer ".length);
				if (tokenFromHeader) {
					throw this.error(
						"Authorization header contains a bearer token but access_token was expected " +
							"in request body parameters",
						args("authorization_header", authHeader),
					);
				}
			}
		}
		const accessTokenElementFromQuery = env.getElementFromObject(
			"incoming_request",
			"query_string_params.access_token",
		);

		if (accessTokenElementFromQuery != null) {
			throw this.error(
				"Request contains access_token parameter in query string which is not allowed",
				args("access_token_query_parameter", accessTokenElementFromQuery),
			);
		}

		const accessTokenElementFromForm = env.getElementFromObject("incoming_request", "body_form_params.access_token");
		let tokenFromBody: string | null = null;
		if (accessTokenElementFromForm == null) {
			throw this.error("Could not find an access_token parameter in request body parameters");
		} else {
			if (isJsonPrimitive(accessTokenElementFromForm)) {
				tokenFromBody = OIDFJSON.getString(accessTokenElementFromForm);
				env.putString("incoming_access_token", tokenFromBody);
				this.logSuccess("Found access token in incoming body parameters", args("access_token", tokenFromBody));
				return env;
			} else {
				//unexpected type
				throw this.error(
					"Request body contains multiple access_token parameters",
					args("access_token", accessTokenElementFromForm),
				);
			}
		}
	}
}

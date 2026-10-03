import {
	AbstractCondition,
	args,
	isJsonPrimitive,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

/**
 * extract either from headers or parameters
 * but don't allow more than one (https://tools.ietf.org/html/rfc6750#section-2
 *    Clients MUST NOT use more
 *    than one method to transmit the token in each request.)
 */
export class OIDCCExtractBearerAccessTokenFromRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["incoming_request"] };
	static override post: EnvironmentRequirements = { strings: ["incoming_access_token"] };

	override evaluate(env: Environment): Environment {
		let tokenFromHeader: string | null = null;
		let tokenFromParams: string | null = null;

		const authHeader = env.getString("incoming_request", "headers.authorization");
		if (authHeader) {
			if (authHeader.toLowerCase().startsWith("bearer ")) {
				tokenFromHeader = authHeader.substring("bearer ".length);
			}
		}
		const accessTokenElementFromForm = env.getElementFromObject("incoming_request", "body_form_params.access_token");
		const accessTokenElementFromQuery = env.getElementFromObject(
			"incoming_request",
			"query_string_params.access_token",
		);

		if (accessTokenElementFromQuery != null) {
			throw this.error(
				"Request contains access_token parameter in query string",
				args("access_token_query_parameter", accessTokenElementFromQuery),
			);
		}

		if (accessTokenElementFromForm != null) {
			if (isJsonPrimitive(accessTokenElementFromForm)) {
				tokenFromParams = OIDFJSON.getString(accessTokenElementFromForm);
			} else {
				//unexpected type
				throw this.error(
					"Request body contains multiple access_token parameters",
					args("access_token", accessTokenElementFromForm),
				);
			}
		}

		if (!tokenFromHeader && !tokenFromParams) {
			throw this.error("Couldn't find a bearer token in request");
		}
		if (tokenFromHeader && tokenFromParams) {
			throw this.error(
				"Found more than one access token in request",
				args("token_from_authorization_header", tokenFromHeader, "token_from_request_parameters", tokenFromParams),
			);
		}
		let incomingAccessToken: string | null = null;
		if (tokenFromHeader) {
			incomingAccessToken = tokenFromHeader;
		} else {
			incomingAccessToken = tokenFromParams;
		}

		env.putString("incoming_access_token", incomingAccessToken);
		this.logSuccess("Found access token on incoming request", args("access_token", incomingAccessToken));

		return env;
	}
}

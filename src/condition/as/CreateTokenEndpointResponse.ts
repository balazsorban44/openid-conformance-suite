import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateTokenEndpointResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["access_token", "token_type"] }; // note the others are optional
	static override post: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const accessToken = env.getString("access_token");
		const tokenType = env.getString("token_type");
		const idToken = env.getString("id_token");
		const refreshToken = env.getString("refresh_token");
		const scope = env.getString("scope");
		const accessTokenExpiration = env.getString("access_token_expiration");

		if (!accessToken || !tokenType) {
			throw this.error("Missing required access_token or token_type");
		}

		const fapiInteractionId = env.getString("fapi_interaction_id");
		const headers: JsonObject = {};
		if (fapiInteractionId) {
			headers["x-fapi-interaction-id"] = fapiInteractionId;
			env.putObject("token_endpoint_response_headers", headers);
		}

		const tokenEndpointResponse: JsonObject = {};

		tokenEndpointResponse["access_token"] = accessToken;
		tokenEndpointResponse["token_type"] = tokenType;

		if (idToken) {
			tokenEndpointResponse["id_token"] = idToken;
		}

		if (refreshToken) {
			tokenEndpointResponse["refresh_token"] = refreshToken;
		}

		if (scope) {
			tokenEndpointResponse["scope"] = scope;
		}

		if (accessTokenExpiration) {
			// Integer.parseInt throws NumberFormatException on anything that is not an optionally signed integer
			if (!/^[+-]?\d+$/.test(accessTokenExpiration)) {
				throw new Error('For input string: "' + accessTokenExpiration + '"');
			}
			tokenEndpointResponse["expires_in"] = Number(accessTokenExpiration);
		}

		env.putObject("token_endpoint_response", tokenEndpointResponse);

		this.logSuccess(
			args("Created token endpoint response", tokenEndpointResponse, "token_endpoint_response_headers", headers),
		);

		return env;
	}
}

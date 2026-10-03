import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateRefreshTokenRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["refresh_token"] };
	static override post: EnvironmentRequirements = { required: ["token_endpoint_request_form_parameters"] };

	override evaluate(env: Environment): Environment {
		const refreshTokenRequest: JsonObject = {};
		refreshTokenRequest["grant_type"] = "refresh_token";
		refreshTokenRequest["refresh_token"] = env.getString("refresh_token");

		env.putObject("token_endpoint_request_form_parameters", refreshTokenRequest);

		// Reset headers so that we're truly starting a 'new' request
		env.putObject("token_endpoint_request_headers", {});

		this.logSuccess("Created token endpoint request parameters", refreshTokenRequest);

		return env;
	}
}

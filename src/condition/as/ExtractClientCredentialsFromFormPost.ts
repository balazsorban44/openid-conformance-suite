import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ExtractClientCredentialsFromFormPost extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["client_authentication"] };

	override evaluate(env: Environment): Environment {
		if (env.containsObject("client_authentication")) {
			throw this.error("Found existing client authentication");
		}

		const clientId = env.getString("token_endpoint_request", "body_form_params.client_id");
		const clientSecret = env.getString("token_endpoint_request", "body_form_params.client_secret");

		if (!clientId || !clientSecret) {
			throw this.error("Couldn't find client credentials in form post");
		}

		const clientAuthentication: JsonObject = {};
		clientAuthentication["client_id"] = clientId;
		clientAuthentication["client_secret"] = clientSecret;
		clientAuthentication["method"] = "client_secret_post";

		env.putObject("client_authentication", clientAuthentication);

		this.logSuccess("Extracted client authentication", clientAuthentication);

		return env;
	}
}

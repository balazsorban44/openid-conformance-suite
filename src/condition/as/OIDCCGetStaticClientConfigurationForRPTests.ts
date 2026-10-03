import {
	AbstractCondition,
	has,
	isJsonObject,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
} from "../../framework/index.ts";

export class OIDCCGetStaticClientConfigurationForRPTests extends AbstractCondition {
	/**
	 * Converts single value form fields to arrays
	 * - redirect_uri to redirect_uris
	 * - post_logout_redirect_uri to post_logout_redirect_uris
	 * @param env
	 * @return
	 */
	static override pre: EnvironmentRequirements = { required: ["config"] };
	static override post: EnvironmentRequirements = { required: ["client"], strings: ["client_id"] };

	override evaluate(env: Environment): Environment {
		// make sure we've got a client object
		const client = env.getElementFromObject("config", "client");
		if (client == null || !isJsonObject(client)) {
			throw this.error("Definition for client not present in supplied configuration");
		} else {
			// we've got a client object, put it in the environment
			const clientObject = client;
			if (has(clientObject, "redirect_uri")) {
				const redirectUri = OIDFJSON.getString(clientObject["redirect_uri"]);
				const redirectUrisArray: JsonArray = [];
				redirectUrisArray.push(redirectUri);
				delete clientObject["redirect_uri"];
				clientObject["redirect_uris"] = redirectUrisArray;
			}

			//post_logout_redirect_uri to post_logout_redirect_uris
			if (has(clientObject, "post_logout_redirect_uri")) {
				const redirectUri = OIDFJSON.getString(clientObject["post_logout_redirect_uri"]);
				const redirectUrisArray: JsonArray = [];
				redirectUrisArray.push(redirectUri);
				delete clientObject["post_logout_redirect_uri"];
				clientObject["post_logout_redirect_uris"] = redirectUrisArray;
			}

			env.putObject("client", clientObject);

			// pull out the client ID and put it in the root environment for easy access
			env.putString("client_id", env.getString("client", "client_id"));

			this.logSuccess("Found a static client object", client);

			return env;
		}
	}
}

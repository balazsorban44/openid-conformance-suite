import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
	type JsonArray,
} from "../../framework/index.ts";

export class AddMultipleRedirectUriToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["dynamic_registration_request"],
		strings: ["redirect_uri"],
	};
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		if (!env.containsObject("dynamic_registration_request")) {
			throw this.error("No dynamic registration request found");
		}

		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		const redirectUri = env.getString("redirect_uri");
		if (!redirectUri) {
			throw this.error("No redirect_uri found");
		}

		const redirectUris: JsonArray = [];
		redirectUris.push(redirectUri);
		redirectUris.push("https://example.org/redirect");
		dynamicRegistrationRequest["redirect_uris"] = redirectUris;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added redirect_uris array to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}

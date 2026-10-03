import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddSectorIdentifierUriToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"], strings: ["base_url"] };
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		// Use external_url_override if available, since the sector_identifier_uri must be
		// reachable by the external authorization server (e.g. via ngrok, not localhost)
		let baseUri = env.getString("external_url_override");
		if (!baseUri) {
			baseUri = env.getString("base_url");
		}

		const sectorIdentifierUri = baseUri + "/redirect_uris.json";

		dynamicRegistrationRequest["sector_identifier_uri"] = sectorIdentifierUri;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added sector_identifier_uri to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}

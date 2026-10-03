import {
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { AbstractJsonUriIsValidAndHttps } from "./AbstractJsonUriIsValidAndHttps.ts";

export class VerifyClientManagementCredentials extends AbstractJsonUriIsValidAndHttps {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;

		if (!("registration_client_uri" in client) && !("registration_access_token" in client)) {
			this.log("Dynamic registration returned neither registration_client_uri nor registration_access_token");
			return env;
		}

		if (!("registration_client_uri" in client)) {
			throw this.error("Dynamic registration returned registration_access_token but not registration_client_uri");
		}
		if (!("registration_access_token" in client)) {
			throw this.error("Dynamic registration returned registration_client_uri but not registration_access_token");
		}

		const registrationClientUri = OIDFJSON.getString(client["registration_client_uri"]);
		const registrationAccessToken = OIDFJSON.getString(client["registration_access_token"]);

		if (!registrationClientUri) {
			throw this.error("registration_client_uri must not be an empty string");
		}

		let url: URL;
		try {
			url = new URL(registrationClientUri);
		} catch {
			throw this.error(AbstractJsonUriIsValidAndHttps.errorMessageInvalidURL);
		}
		// Java's URL.getProtocol() has no trailing colon
		if (url.protocol.replace(/:$/, "") !== AbstractJsonUriIsValidAndHttps.requiredProtocol) {
			throw this.error(
				"URL for client management point does not use " + AbstractJsonUriIsValidAndHttps.requiredProtocol + " scheme",
				args("required", AbstractJsonUriIsValidAndHttps.requiredProtocol, "actual", registrationClientUri),
			);
		}

		if (!registrationAccessToken) {
			throw this.error("registration_access_token must not be an empty string");
		}

		this.logSuccess(
			"Verified dynamic registration management credentials",
			args("registration_client_uri", registrationClientUri, "registration_access_token", registrationAccessToken),
		);

		return env;
	}
}

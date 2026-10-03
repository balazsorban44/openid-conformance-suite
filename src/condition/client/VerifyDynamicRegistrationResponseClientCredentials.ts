import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class VerifyDynamicRegistrationResponseClientCredentials extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const clientObject = env.getObject("client") as JsonObject;
		const clientSecretEl = clientObject["client_secret"];

		if (clientSecretEl === undefined) {
			this.log(
				"Skipped check for valid credential information for token_endpoint_auth_method in client registration response",
			);
		} else {
			const clientSecret = OIDFJSON.getString(clientSecretEl);
			const clientSecretExpiresAtEl = clientObject["client_secret_expires_at"];
			const clientSecretExpiresAt =
				clientSecretExpiresAtEl === undefined ? null : OIDFJSON.getLong(clientSecretExpiresAtEl);
			if (clientSecretExpiresAt == null) {
				throw this.error(
					"Missing client_secret_expires_at for token_endpoint_auth_method in client registration response",
				);
			}

			this.logSuccess(
				"Found required credential information for token_endpoint_auth_method in client registration response",
				args("client_secret", clientSecret, "client_secret_expires_at", clientSecretExpiresAt),
			);
		}

		return env;
	}
}

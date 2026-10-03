import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ValidateInitiateLoginUriInConfigurationResponse extends AbstractCondition {
	static readonly INITIATE_LOGIN_URI = "initiate_login_uri";

	static override pre: EnvironmentRequirements = {
		required: ["registration_client_endpoint_response"],
		strings: [ValidateInitiateLoginUriInConfigurationResponse.INITIATE_LOGIN_URI],
	};

	override evaluate(env: Environment): Environment {
		const INITIATE_LOGIN_URI = ValidateInitiateLoginUriInConfigurationResponse.INITIATE_LOGIN_URI;
		const returnedUri = env.getString("registration_client_endpoint_response", "body_json." + INITIATE_LOGIN_URI);
		const initiateLoginUri = env.getString(INITIATE_LOGIN_URI);

		if (returnedUri == null) {
			throw this.error(INITIATE_LOGIN_URI + " missing from client configuration response.");
		}

		if (returnedUri !== initiateLoginUri) {
			throw this.error(
				INITIATE_LOGIN_URI + " in client configuration response does not match the value the client registered.",
				args("requested", initiateLoginUri, "actual", returnedUri),
			);
		}

		this.logSuccess(INITIATE_LOGIN_URI + " in configuration response is correct.", args("actual", returnedUri));

		return env;
	}
}

import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ValidateInitiateLoginUriInRegistrationResponse extends AbstractCondition {
	static readonly INITIATE_LOGIN_URI = "initiate_login_uri";

	static override pre: EnvironmentRequirements = {
		required: ["client"],
		strings: [ValidateInitiateLoginUriInRegistrationResponse.INITIATE_LOGIN_URI],
	};

	override evaluate(env: Environment): Environment {
		const INITIATE_LOGIN_URI = ValidateInitiateLoginUriInRegistrationResponse.INITIATE_LOGIN_URI;
		const returnedUri = env.getString("client", INITIATE_LOGIN_URI);
		const initiateLoginUri = env.getString(INITIATE_LOGIN_URI);

		if (returnedUri == null) {
			throw this.error(INITIATE_LOGIN_URI + " missing from client registration response.");
		}

		if (returnedUri !== initiateLoginUri) {
			throw this.error(
				INITIATE_LOGIN_URI + " in client registration response does not match the value in the request.",
				args("requested", initiateLoginUri, "actual", returnedUri),
			);
		}

		this.logSuccess(INITIATE_LOGIN_URI + " in registration response is correct.", args("actual", returnedUri));

		return env;
	}
}

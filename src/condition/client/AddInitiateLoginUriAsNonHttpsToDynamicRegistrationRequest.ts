import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddInitiateLoginUriAsNonHttpsToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["dynamic_registration_request"],
		strings: ["initiate_login_uri"],
	};
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		let initiateLoginUri = env.getString("initiate_login_uri") as string;

		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		initiateLoginUri = initiateLoginUri.replaceAll("https://", "http://");

		dynamicRegistrationRequest["initiate_login_uri"] = initiateLoginUri;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added non-https version of initiate_login_uri to dynamic registration request",
			args("initiate_login_uri", initiateLoginUri),
		);

		return env;
	}
}

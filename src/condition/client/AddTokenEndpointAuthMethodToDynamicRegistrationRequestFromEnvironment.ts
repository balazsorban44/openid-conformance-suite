import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddTokenEndpointAuthMethodToDynamicRegistrationRequestFromEnvironment extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["dynamic_registration_request"],
		strings: ["client_auth_type"],
	};
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;
		const clientAuthType = env.getString("client_auth_type") as string;

		dynamicRegistrationRequest["token_endpoint_auth_method"] = clientAuthType;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added token endpoint auth method to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}

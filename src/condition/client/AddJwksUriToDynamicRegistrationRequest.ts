import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddJwksUriToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"], strings: ["jwks_uri"] };
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		const jwksUri = env.getString("jwks_uri") as string;

		dynamicRegistrationRequest["jwks_uri"] = jwksUri;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added jwks_uri to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}

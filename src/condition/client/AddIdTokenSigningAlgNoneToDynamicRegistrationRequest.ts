import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddIdTokenSigningAlgNoneToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"] };
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		dynamicRegistrationRequest["id_token_signed_response_alg"] = "none";

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added id_token_signed_response_alg to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}

import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddPolicyUriToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["dynamic_registration_request"],
		strings: ["policy_uri"],
	};
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		const policyUri = env.getString("policy_uri") as string;

		dynamicRegistrationRequest["policy_uri"] = policyUri;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added policy_uri to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}

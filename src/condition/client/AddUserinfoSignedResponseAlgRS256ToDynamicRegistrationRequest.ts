import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddUserinfoSignedResponseAlgRS256ToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"] };
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		dynamicRegistrationRequest["userinfo_signed_response_alg"] = "RS256";

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added userinfo_signed_response_alg=RS256 to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}

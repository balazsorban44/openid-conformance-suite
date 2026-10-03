import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddTosUriToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"], strings: ["tos_uri"] };
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		const tosUri = env.getString("tos_uri") as string;

		dynamicRegistrationRequest["tos_uri"] = tosUri;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added tos_uri to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}

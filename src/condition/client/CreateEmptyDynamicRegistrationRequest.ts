import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateEmptyDynamicRegistrationRequest extends AbstractCondition {
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		// create an empty JSON to act as the registration request
		const dynamicRegistrationRequest: JsonObject = {};

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log("Created empty dynamic registration request");

		return env;
	}
}

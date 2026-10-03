import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
	type JsonArray,
} from "../../framework/index.ts";

export class AddResponseTypesArrayToDynamicRegistrationRequestFromEnvironment extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["dynamic_registration_request"],
		strings: ["response_type"],
	};
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;
		const responseType = env.getString("response_type") as string;

		const responseTypes: JsonArray = [];
		responseTypes.push(responseType);

		dynamicRegistrationRequest["response_types"] = responseTypes;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added response_types array to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}

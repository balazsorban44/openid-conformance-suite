import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CheckNoErrorFromDynamicRegistrationEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const error = env.getElementFromObject("dynamic_registration_endpoint_response", "body_json.error");

		if (error != null) {
			throw this.error(
				"'error' field found in response from dynamic registration endpoint.",
				env.getObject("dynamic_registration_endpoint_response") as JsonObject,
			);
		}

		this.logSuccess("Dynamic registration endpoint did not return an error.");

		return env;
	}
}

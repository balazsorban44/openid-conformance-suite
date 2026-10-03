import {
	AbstractCondition,
	isJsonObject,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class StoreOriginalClient2Configuration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["config"] };
	static override post: EnvironmentRequirements = { required: ["original_client_config"] };

	override evaluate(env: Environment): Environment {
		const dynamicClientRegistrationTemplate = env.getElementFromObject("config", "client2");
		if (dynamicClientRegistrationTemplate == null || !isJsonObject(dynamicClientRegistrationTemplate)) {
			// we don't actually need anything; if no client_name is given we'll pick one
			env.putObject("original_client_config", {} as JsonObject);
			this.log("No client details on configuration, created an empty original_client_config object.");
		} else {
			// we've got a client object, put it in the environment
			env.putObject("original_client_config", dynamicClientRegistrationTemplate);

			this.log(
				"Created original_client_config object from the client configuration.",
				dynamicClientRegistrationTemplate,
			);
		}
		return env;
	}
}

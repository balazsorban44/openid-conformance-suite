import {
	AbstractCondition,
	isJsonObject,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class GetStaticClient2Configuration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["config"] };
	static override post: EnvironmentRequirements = { required: ["client2"] };

	override evaluate(env: Environment): Environment {
		if (!env.containsObject("config")) {
			throw this.error("Couldn't find a configuration");
		}

		// make sure we've got a client object
		const client = env.getElementFromObject("config", "client2");
		if (client == null || !isJsonObject(client)) {
			throw this.error("Definition for client2 not present in supplied configuration");
		} else {
			// we've got a client object, put it in the environment
			env.putObject("client2", client);

			this.logSuccess("Found a static second client object", client);
			return env;
		}
	}
}

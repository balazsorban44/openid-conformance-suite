import {
	AbstractCondition,
	isJsonObject,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class GetStaticClientConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["config"] };
	static override post: EnvironmentRequirements = { required: ["client"], strings: ["client_id"] };

	override evaluate(env: Environment): Environment {
		// make sure we've got a client object
		const clientEl = env.getElementFromObject("config", "client");
		if (clientEl == null || !isJsonObject(clientEl)) {
			throw this.error("As static client was selected, the test configuration must contain a client configuration");
		} else {
			const client = clientEl;
			// we've got a client object, put it in the environment
			env.putObject("client", client);

			const clientId = client["client_id"];
			if (clientId === undefined) {
				throw this.error("As static client was selected, the test configuration must contain a client_id");
			}
			if (typeof clientId !== "string") {
				throw this.error("client_id in test configuration is not a string");
			}

			// pull out the client ID and put it in the root environment for easy access
			env.putString("client_id", OIDFJSON.getString(clientId));

			this.logSuccess("Found a static client object", client);
			return env;
		}
	}
}

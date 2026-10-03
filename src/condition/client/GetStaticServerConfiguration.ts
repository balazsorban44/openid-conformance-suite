import {
	AbstractCondition,
	args,
	isJsonObject,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class GetStaticServerConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["config"] };
	static override post: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const discoveryUrl = env.getString("config", "server.discoveryUrl");
		const iss = env.getString("config", "server.discoveryIssuer");

		if (discoveryUrl || iss) {
			throw this.error(
				"Test set to use static server configuration but test configuration contains discovery information",
				args("discoveryUrl", discoveryUrl, "discoveryIssuer", iss),
			);
		}

		// make sure we've got a server object
		const server = env.getElementFromObject("config", "server");
		if (server == null || !isJsonObject(server)) {
			throw this.error("Couldn't find server object in configuration");
		} else {
			// we've got a server object, put it in the environment
			env.putObject("server", server);

			this.logSuccess("Found a static server object", server);
			return env;
		}
	}
}

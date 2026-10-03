import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExtractClientNameFromStoredConfig extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["original_client_config"] };

	override evaluate(env: Environment): Environment {
		// pull out the client name and put it in the root environment for easy access (if there is one)
		const clientName = env.getString("original_client_config", "client_name");
		if (clientName) {
			env.putString("client_name", clientName);
		}

		this.log(
			"Extracted client_name from stored client configuration.",
			args("client_name", clientName ? clientName : null),
		);

		return env;
	}
}

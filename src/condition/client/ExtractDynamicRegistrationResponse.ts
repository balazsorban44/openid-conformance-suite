import {
	AbstractCondition,
	args,
	deepCopy,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ExtractDynamicRegistrationResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_endpoint_response"] };
	static override post: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getElementFromObject("dynamic_registration_endpoint_response", "body_json") as
			| JsonObject
			| null
			| undefined;
		if (client == null) {
			throw this.error("No json response from dynamic registration endpoint");
		}

		env.putObject("client", deepCopy(client));

		const clientId = client["client_id"];
		if (clientId === undefined) {
			throw this.error("no client id in dynamic registration response");
		}

		this.logSuccess("Extracted client from dynamic registration response", args("client_id", clientId));

		return env;
	}
}

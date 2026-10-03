import {
	AbstractCondition,
	args,
	has,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class EnsureClientDoesNotHaveBothJwksAndJwksUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;

		if (has(client, "jwks") && has(client, "jwks_uri")) {
			throw this.error("Client cannot have both jwks and jwks_uri at the same time", args("client", client));
		}
		this.logSuccess("Client does not have both jwks and jwks_uri set", args("client", client));
		return env;
	}
}

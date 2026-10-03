import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class SetDpopHtmHtuForTokenEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server", "dpop_proof_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("dpop_proof_claims") as JsonObject;

		const tokenEndpoint =
			env.getString("token_endpoint") != null
				? env.getString("token_endpoint")
				: env.getString("server", "token_endpoint");

		if (!tokenEndpoint) {
			throw this.error(
				"token_endpoint not found in server configuration",
				args("server_config", env.getObject("server")),
			);
		}

		const resourceMethod = "POST";

		claims["htm"] = resourceMethod;
		claims["htu"] = tokenEndpoint;

		this.logSuccess("Added htm/htu to DPoP proof claims", claims);

		return env;
	}
}

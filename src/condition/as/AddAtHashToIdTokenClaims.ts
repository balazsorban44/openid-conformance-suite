import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddAtHashToIdTokenClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token_claims"], strings: ["at_hash"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("id_token_claims") as JsonObject;

		const hash = env.getString("at_hash");

		claims["at_hash"] = hash;

		env.putObject("id_token_claims", claims);

		this.logSuccess("Added at_hash to ID token claims", args("id_token_claims", claims, "at_hash", hash));

		return env;
	}
}

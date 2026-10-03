import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddCHashToIdTokenClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token_claims"], strings: ["c_hash"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("id_token_claims") as JsonObject;

		const hash = env.getString("c_hash");

		claims["c_hash"] = hash;

		env.putObject("id_token_claims", claims);

		this.logSuccess("Added c_hash to ID token claims", args("id_token_claims", claims, "c_hash", hash));

		return env;
	}
}

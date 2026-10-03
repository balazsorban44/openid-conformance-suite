import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class AddSidToIdTokenClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token_claims", "session_state_data"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("id_token_claims") as JsonObject;

		const sid = env.getString("session_state_data", "sid");

		claims["sid"] = sid;

		env.putObject("id_token_claims", claims);

		this.logSuccess("Added sid to ID token claims", args("id_token_claims", claims, "sid", sid));

		return env;
	}
}

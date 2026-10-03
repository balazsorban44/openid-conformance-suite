import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddInvalidAudValueToIdToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token_claims"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("id_token_claims") as JsonObject;

		const aud = env.getString("id_token_claims", "aud");

		//Add number 1 onto end of aud string
		const concat = `${aud}1`;

		claims["aud"] = concat;

		env.putObject("id_token_claims", claims);

		this.logSuccess("Added invalid aud to ID token claims", args("id_token_claims", claims, "aud", concat));

		return env;
	}
}

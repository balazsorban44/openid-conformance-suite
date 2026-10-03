import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddInvalidNonceValueToIdToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token_claims"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("id_token_claims") as JsonObject;

		const nonce = env.getString("id_token_claims", "nonce");

		//Add number 1 onto end of nonce string
		const concat = `${nonce}1`;

		claims["nonce"] = concat;

		env.putObject("id_token_claims", claims);

		this.logSuccess("Added invalid nonce to ID token claims", args("id_token_claims", claims, "nonce", concat));

		return env;
	}
}

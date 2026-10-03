import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddInvalidIssValueToIdToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token_claims"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("id_token_claims") as JsonObject;

		const iss = env.getString("id_token_claims", "iss");

		//Add number 1 onto end of iss string
		const concat = `${iss}1`;

		claims["iss"] = concat;

		env.putObject("id_token_claims", claims);

		this.logSuccess("Added invalid iss to ID token claims", args("id_token_claims", claims, "iss", concat));

		return env;
	}
}

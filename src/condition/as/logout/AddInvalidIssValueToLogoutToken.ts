import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class AddInvalidIssValueToLogoutToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["logout_token_claims"] };
	static override post: EnvironmentRequirements = { required: ["logout_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("logout_token_claims") as JsonObject;

		const iss = env.getString("logout_token_claims", "iss");

		//Append "INVALID" to iss
		const concat = `${iss}INVALID`;

		claims["iss"] = concat;

		env.putObject("logout_token_claims", claims);

		this.log("Added invalid iss to logout token claims", args("logout_token_claims", claims, "iss", concat));

		return env;
	}
}

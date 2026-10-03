import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class AddInvalidAudValueToLogoutToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["logout_token_claims"] };
	static override post: EnvironmentRequirements = { required: ["logout_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("logout_token_claims") as JsonObject;

		const aud = env.getString("logout_token_claims", "aud");

		//Append "INVALID" to aud
		const concat = `${aud}INVALID`;

		claims["aud"] = concat;

		env.putObject("logout_token_claims", claims);

		this.log("Added invalid aud to logout token claims", args("logout_token_claims", claims, "aud", concat));

		return env;
	}
}

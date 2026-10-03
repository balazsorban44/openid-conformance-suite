import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddAuthTimeToIdTokenClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["auth_time"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("id_token_claims") as JsonObject;

		const authTime = env.getString("auth_time") as string;
		// Long.parseLong throws NumberFormatException on anything that is not an optionally signed integer
		if (!/^[+-]?\d+$/.test(authTime)) {
			throw new Error('For input string: "' + authTime + '"');
		}
		claims["auth_time"] = Number(authTime);

		env.putObject("id_token_claims", claims);

		this.logSuccess("Added auth_time to ID token claims", args("id_token_claims", claims, "auth_time", authTime));

		return env;
	}
}

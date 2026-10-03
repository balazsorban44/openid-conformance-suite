import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CheckIdTokenSubMatchesLogoutToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token", "logout_token"] };

	override evaluate(env: Environment): Environment {
		const idToken = (env.getObject("id_token") as JsonObject)["claims"] as JsonObject;
		const logoutToken = (env.getObject("logout_token") as JsonObject)["claims"] as JsonObject;

		const subIdToken = env.getString("id_token", "claims.sub");

		const subLogoutToken = env.getString("logout_token", "claims.sub");

		// UPSTREAM: Java's subIdToken.equals(...) throws a NullPointerException when the id_token has no sub
		if (subIdToken !== subLogoutToken) {
			throw this.error(
				"The id_token and the logout_token contain different sub claims, but must contain the same sub.",
				args("id_token", idToken, "logout_token", logoutToken),
			);
		}

		this.logSuccess(
			"sub from the id_token matches that in the logout_token",
			args("id_token", idToken, "logout_token", logoutToken),
		);

		return env;
	}
}

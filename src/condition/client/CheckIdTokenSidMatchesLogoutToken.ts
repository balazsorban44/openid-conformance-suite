import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CheckIdTokenSidMatchesLogoutToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token", "logout_token"] };

	override evaluate(env: Environment): Environment {
		const idToken = (env.getObject("id_token") as JsonObject)["claims"] as JsonObject;
		const logoutToken = (env.getObject("logout_token") as JsonObject)["claims"] as JsonObject;

		const sidIdToken = env.getString("id_token", "claims.sid");

		const sidLogoutToken = env.getString("logout_token", "claims.sid");

		// UPSTREAM: Java's sidIdToken.equals(...) throws a NullPointerException when the id_token has no sid
		if (sidIdToken !== sidLogoutToken) {
			throw this.error(
				"The id_token and the logout_token contain different sid claims, but must contain the same sid.",
				args("id_token", idToken, "logout_token", logoutToken),
			);
		}

		this.logSuccess(
			"sid in the id_token matches that in the logout_token",
			args("id_token", idToken, "logout_token", logoutToken),
		);

		return env;
	}
}

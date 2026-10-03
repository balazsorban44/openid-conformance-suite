import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CheckIdTokenSidMatchesFrontChannelLogoutRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token", "frontchannel_logout_request"] };

	override evaluate(env: Environment): Environment {
		const idToken = (env.getObject("id_token") as JsonObject)["claims"] as JsonObject;
		const logoutRequest = (env.getObject("frontchannel_logout_request") as JsonObject)[
			"query_string_params"
		] as JsonObject;

		const sidIdToken = env.getString("id_token", "claims.sid");

		const sidFrontChannel = env.getString("frontchannel_logout_request", "query_string_params.sid");

		if (!sidFrontChannel) {
			throw this.error("'sid' missing from frontchannel logout request");
		}

		// UPSTREAM: Java's sidIdToken.equals(...) throws a NullPointerException when the id_token has no sid
		if (sidIdToken !== sidFrontChannel) {
			throw this.error(
				"The id_token and the frontchannel logout request contain different sid claims, but must contain the same sid.",
				args("id_token", idToken, "logout_request", logoutRequest),
			);
		}

		this.logSuccess(
			"sid is the same in the id_token and the front channel logout request",
			args("id_token", idToken, "logout_request", logoutRequest),
		);

		return env;
	}
}

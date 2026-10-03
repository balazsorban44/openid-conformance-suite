import { randomUUID } from "node:crypto";
import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class GenerateLogoutTokenClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["user_info", "client", "session_state_data"],
		strings: ["issuer"],
	};
	static override post: EnvironmentRequirements = { required: ["logout_token_claims"] };

	override evaluate(env: Environment): Environment {
		const subject = env.getString("user_info", "sub");
		const issuer = env.getString("issuer");
		const clientId = env.getString("client", "client_id");

		const claims: JsonObject = {};
		claims["iss"] = issuer;
		claims["sub"] = subject;
		claims["aud"] = clientId;
		claims["jti"] = randomUUID();

		const sid = env.getString("session_state_data", "sid");
		if (sid != null) {
			claims["sid"] = sid;
		}

		const events: JsonObject = {};
		events["http://schemas.openid.net/event/backchannel-logout"] = {};
		claims["events"] = events;

		const iat = Math.floor(Date.now() / 1000);
		claims["iat"] = iat;

		//OPs are encouraged to use short expiration times in Logout Tokens, preferably at most two minutes in the future
		const exp = iat + 2 * 60;
		claims["exp"] = exp;

		claims["ignored_claim"] =
			"Logout Tokens MAY contain other Claims. Any Claims used that are not understood MUST be ignored.";

		env.putObject("logout_token_claims", claims);

		this.logSuccess("Created Logout Token Claims", claims);

		return env;
	}
}

import {
	AbstractCondition,
	args,
	isJsonArray,
	isJsonObject,
	jsonArrayContains,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

const DAY_MILLIS = 24 * 60 * 60 * 1000;

export class ValidateLogoutTokenClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["logout_token", "server", "client"] };

	private timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing

	override evaluate(env: Environment): Environment {
		const clientId = env.getString("client", "client_id"); // to check the audience
		const issuer = env.getString("server", "issuer"); // to validate the issuer
		const now = Date.now(); // to check timestamps

		if (!clientId || !issuer) {
			throw this.error("Couldn't find values to test token against");
		}

		// checks are in order listed in https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
		// iss
		//REQUIRED. Issuer Identifier, as specified in Section 2 of [OpenID.Core].
		const logoutTokenIss = env.getString("logout_token", "claims.iss");
		if (logoutTokenIss == null) {
			throw this.error("'iss' claim missing");
		}
		if (issuer !== logoutTokenIss) {
			throw this.error("Issuer mismatch", args("expected", issuer, "actual", logoutTokenIss));
		}

		//sub
		//OPTIONAL. Subject Identifier, as specified in Section 2 of [OpenID.Core].
		// checked in CheckIdTokenSubMatchesLogoutToken & CheckLogoutTokenHasSubOrSid

		//aud
		//REQUIRED. Audience(s), as specified in Section 2 of [OpenID.Core].
		const aud = env.getElementFromObject("logout_token", "claims.aud");
		if (aud == null) {
			throw this.error("'aud' claim missing");
		}
		if (isJsonArray(aud)) {
			if (!jsonArrayContains(aud, clientId)) {
				throw this.error("'aud' array does not contain our client id", args("expected", clientId, "actual", aud));
			}
		} else {
			if (clientId !== OIDFJSON.getString(aud)) {
				throw this.error("'aud' is not our client id", args("expected", clientId, "actual", aud));
			}
		}

		//iat
		//REQUIRED. Issued at time, as specified in Section 2 of [OpenID.Core].
		const iat = env.getLong("logout_token", "claims.iat");
		if (iat == null) {
			throw this.error("'iat' claim missing");
		} else {
			if (now + this.timeSkewMillis < iat * 1000) {
				throw this.error("Token 'iat' in the future", args("issued-at", new Date(iat * 1000), "now", new Date(now)));
			}
			if (now - DAY_MILLIS > iat * 1000) {
				throw this.error(
					"'iat' is more than 1 day in the past",
					args("issued-at", new Date(iat * 1000), "now", new Date(now)),
				);
			}
		}

		//jti
		//REQUIRED. Unique identifier for the token, as specified in Section 9 of [OpenID.Core].
		const jti = env.getString("logout_token", "claims.jti");
		if (jti == null) {
			throw this.error("jti missing");
		}

		//events
		//REQUIRED. Claim whose value is a JSON object containing the member name http://schemas.openid.net/event/backchannel-logout. This declares that the JWT is a Logout Token. The corresponding member value MUST be a JSON object and SHOULD be the empty JSON object {}.
		const events = env.getElementFromObject("logout_token", "claims.events");
		if (events == null) {
			throw this.error("'events' claim missing");
		}
		if (!isJsonObject(events)) {
			throw this.error("'events' claim is not a json object");
		}
		const eventsObj = events;
		if (Object.keys(eventsObj).length !== 1) {
			throw this.error("'events' object does not contain exactly 1 entry", eventsObj);
		}
		const eventsValueElement = eventsObj["http://schemas.openid.net/event/backchannel-logout"];
		if (eventsValueElement === undefined) {
			throw this.error(
				"http://schemas.openid.net/event/backchannel-logout entry is missing from 'events' claim",
				eventsObj,
			);
		}
		if (!isJsonObject(eventsValueElement)) {
			throw this.error("http://schemas.openid.net/event/backchannel-logout is not a json object");
		}
		const eventsValue = eventsValueElement;
		if (Object.keys(eventsValue).length !== 0) {
			throw this.error("http://schemas.openid.net/event/backchannel-logout is not an empty object", eventsObj);
		}

		//sid
		//OPTIONAL. Session ID - String identifier for a Session. This represents a Session of a User Agent or device for a logged-in End-User at an RP. Different sid values are used to identify distinct sessions at an OP. The sid value need only be unique in the context of a particular issuer. Its contents are opaque to the RP. Its syntax is the same as an OAuth 2.0 Client Identifier.
		// Checked in CheckIdTokenSidMatchesLogoutToken & CheckLogoutTokenHasSubOrSid

		// nonce checked in CheckLogoutTokenNoNonce

		this.logSuccess("logout token iss, aud, iat, jti and events claims passed validation checks");
		return env;
	}
}

import {
	AbstractCondition,
	args,
	isJsonArray,
	jsonArrayContains,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

const DAY_MILLIS = 24 * 60 * 60 * 1000;

export class ValidateIdToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token", "server", "client"] };

	// TODO: make this configurable
	protected timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing

	/** `now` is an Instant expressed as epoch milliseconds, `iat` is in epoch seconds */
	protected verifyIat(now: number, iat: number): void {
		if (now - this.timeSkewMillis > iat * 1000) {
			// as per OIDCC, the client can reasonably assume servers send iat values that match the current time:
			// "The iat Claim can be used to reject tokens that were issued too far away from the current time, limiting
			// the amount of time that nonces need to be stored to prevent attacks. The acceptable range is Client specific."
			throw this.error(
				"Token 'iat' more than 5 minutes in the past",
				args("issued-at", new Date(iat * 1000), "now", new Date(now)),
			);
		}
	}

	override evaluate(env: Environment): Environment {
		const clientId = env.getString("client", "client_id"); // to check the audience
		const issuer = env.getString("server", "issuer"); // to validate the issuer
		const now = Date.now(); // to check timestamps

		// check all our testable values
		if (!clientId || !issuer) {
			throw this.error("Couldn't find values to test ID token against");
		}

		// checks in the order the claims are listed in https://openid.net/specs/openid-connect-core-1_0.html#IDToken

		const iss = env.getElementFromObject("id_token", "claims.iss");
		if (iss == null) {
			throw this.error("'iss' claim missing");
		}

		if (issuer !== env.getString("id_token", "claims.iss")) {
			throw this.error("Issuer mismatch", args("expected", issuer, "actual", env.getString("id_token", "claims.iss")));
		}

		// sub is checked in CheckForSubjectInIdToken

		const aud = env.getElementFromObject("id_token", "claims.aud");
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

		const exp = env.getLong("id_token", "claims.exp");
		if (exp == null) {
			throw this.error("'exp' claim missing");
		} else {
			if (now - this.timeSkewMillis > exp * 1000) {
				throw this.error("Token expired", args("expiration", new Date(exp * 1000), "now", new Date(now)));
			}
			if (exp * 1000 > now + 50 * 365 * DAY_MILLIS) {
				throw this.error(
					"'exp' is unreasonably far in the future (more than 50 years), this may indicate the value was incorrectly specified in milliseconds instead of seconds",
					args("exp", new Date(exp * 1000), "now", new Date(now)),
				);
			}
		}

		const iat = env.getLong("id_token", "claims.iat");
		if (iat == null) {
			throw this.error("'iat' claim missing");
		}
		if (now + this.timeSkewMillis < iat * 1000) {
			throw this.error("Token 'iat' in the future", args("issued-at", new Date(iat * 1000), "now", new Date(now)));
		}
		this.verifyIat(now, iat);

		// auth_time - optional number
		const authTime = env.getLong("id_token", "claims.auth_time");
		if (authTime != null) {
			if (now - 365 * DAY_MILLIS > authTime * 1000) {
				throw this.error(
					"id_token auth_time is over a year in the past",
					args("auth_time", new Date(authTime * 1000), "now", new Date(now)),
				);
			}
			if (now + this.timeSkewMillis < authTime * 1000) {
				throw this.error(
					"id_token auth_time is in the future",
					args("auth_time", new Date(authTime * 1000), "now", new Date(now)),
				);
			}
		}

		// nonce checked in ValidateIdTokenNonce

		// acr - optional string
		const acr = env.getString("id_token", "claims.acr");
		if (acr != null && acr === "") {
			throw this.error("id_token acr is an empty string");
		}

		// amr - not currently checked

		// azp - not currently checked

		// nbf - not actually part of spec; but JWT defines known behaviour that really should be followed
		const nbf = env.getLong("id_token", "claims.nbf");
		if (nbf != null) {
			if (now + this.timeSkewMillis < nbf * 1000) {
				// this is just something to log, it doesn't make the token invalid
				this.log("Token has future not-before", args("not-before", new Date(nbf * 1000), "now", new Date(now)));
			}
		}

		// jti - also not mentioned in spec (but defined in JWT); not currently checked

		this.logSuccess("ID token iss, aud, exp, iat, auth_time, acr & nbf claims passed validation checks");
		return env;
	}
}

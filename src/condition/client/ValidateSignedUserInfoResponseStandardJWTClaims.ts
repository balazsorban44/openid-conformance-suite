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

export class ValidateSignedUserInfoResponseStandardJWTClaims extends AbstractCondition {
	static readonly USERINFO_OBJECT = "userinfo_object";

	static override pre: EnvironmentRequirements = {
		required: [ValidateSignedUserInfoResponseStandardJWTClaims.USERINFO_OBJECT, "server", "client"],
	};

	// TODO: make this configurable
	private timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing

	override evaluate(env: Environment): Environment {
		const USERINFO_OBJECT = ValidateSignedUserInfoResponseStandardJWTClaims.USERINFO_OBJECT;
		const clientId = env.getString("client", "client_id"); // to check the audience
		const issuer = env.getString("server", "issuer"); // to validate the issuer
		const now = Date.now(); // to check timestamps

		// check all our testable values
		if (!clientId || !issuer) {
			throw this.error("Couldn't find values to test ID token against");
		}

		const iss = env.getElementFromObject(USERINFO_OBJECT, "claims.iss");
		if (iss == null) {
			throw this.error("Missing issuer");
		}

		if (issuer !== env.getString(USERINFO_OBJECT, "claims.iss")) {
			throw this.error(
				"Issuer mismatch",
				args("expected", issuer, "actual", env.getString(USERINFO_OBJECT, "claims.iss")),
			);
		}

		// sub is checked in AbstractVerifyUserInfoAndIdTokenSameSub

		const aud = env.getElementFromObject(USERINFO_OBJECT, "claims.aud");
		if (aud == null) {
			throw this.error("Missing audience");
		}

		if (isJsonArray(aud)) {
			if (!jsonArrayContains(aud, clientId)) {
				throw this.error("Audience not found", args("expected", clientId, "actual", aud));
			}
		} else if (typeof aud === "string") {
			if (clientId !== OIDFJSON.getString(aud)) {
				throw this.error("Audience mismatch", args("expected", clientId, "actual", aud));
			}
		} else {
			throw this.error("'aud' is neither a string nor an array");
		}

		const exp = env.getLong(USERINFO_OBJECT, "claims.exp");
		if (exp != null) {
			if (now - this.timeSkewMillis > exp * 1000) {
				throw this.error("response expired", args("expiration", new Date(exp * 1000), "now", new Date(now)));
			}
			if (exp * 1000 > now + 50 * 365 * DAY_MILLIS) {
				throw this.error(
					"'exp' is unreasonably far in the future (more than 50 years), this may indicate the value was incorrectly specified in milliseconds instead of seconds",
					args("exp", new Date(exp * 1000), "now", new Date(now)),
				);
			}
		}

		const iat = env.getLong(USERINFO_OBJECT, "claims.iat");
		if (iat != null) {
			if (now + this.timeSkewMillis < iat * 1000) {
				throw this.error(
					"response issued in the future",
					args("issued-at", new Date(iat * 1000), "now", new Date(now)),
				);
			}
			if (now - DAY_MILLIS > iat * 1000) {
				throw this.error(
					"'iat' is more than 1 day in the past",
					args("issued-at", new Date(iat * 1000), "now", new Date(now)),
				);
			}
		}

		const nbf = env.getLong(USERINFO_OBJECT, "claims.nbf");
		if (nbf != null) {
			if (now + this.timeSkewMillis < nbf * 1000) {
				throw this.error(
					"response has future not-before",
					args("not-before", new Date(nbf * 1000), "now", new Date(now)),
				);
			}
		}

		// jti - also not mentioned in spec (but defined in JWT); not currently checked

		this.logSuccess(
			"Signed userinfo response iss and aud claims passed validation checks. If present, exp, iat and nbf are also valid.",
		);
		return env;
	}
}

import {
	AbstractCondition,
	args,
	isJsonArray,
	jsonArrayContains,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class ValidateClientAssertionClaims extends AbstractCondition {
	// TODO: make this configurable
	private timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing

	private oneDayMillis = 60 * 60 * 24 * 1000; // Duration for one day

	static override pre: EnvironmentRequirements = { required: ["server", "client"] };

	override evaluate(env: Environment): Environment {
		const now = Date.now(); // to check timestamps (Instant, in epoch milliseconds)

		const clientId = env.getString("client", "client_id"); // to check the client
		const issuer = env.getString("server", "issuer"); // to validate the issuer

		// check all our testable values
		if (!clientId || !issuer) {
			throw this.error(
				"Couldn't find issuer or client or token endpoint values in the test configuration to test the assertion",
			);
		}

		const iss = env.getElementFromObject("client_assertion", "claims.iss");
		if (iss === undefined) {
			throw this.error("Missing iss");
		}

		if (clientId !== env.getString("client_assertion", "claims.iss")) {
			throw this.error(
				"Issuer mismatch",
				args("expected", clientId, "actual", env.getString("client_assertion", "claims.iss")),
			);
		}

		this.validateAud(env);

		const sub = env.getElementFromObject("client_assertion", "claims.sub");
		if (sub === undefined) {
			throw this.error("Missing sub");
		}

		if (clientId !== env.getString("client_assertion", "claims.sub")) {
			throw this.error(
				"Subject mismatch",
				args("expected", clientId, "actual", env.getString("client_assertion", "claims.sub")),
			);
		}

		const jti = env.getElementFromObject("client_assertion", "claims.jti");
		if (jti === undefined) {
			throw this.error("Missing JWT ID");
		}

		const nbf = env.getLong("client_assertion", "claims.nbf");
		if (nbf != null) {
			if (now + this.timeSkewMillis < nbf * 1000) {
				throw this.error(
					"Assertion 'nbf' value is in the future'",
					args("not-before", new Date(nbf * 1000), "now", new Date(now)),
				);
			}
		}

		const exp = env.getLong("client_assertion", "claims.exp");
		if (exp == null) {
			throw this.error("Missing exp");
		} else {
			if (now - this.timeSkewMillis > exp * 1000) {
				throw this.error("Assertion expired", args("expiration", new Date(exp * 1000), "now", new Date(now)));
			}

			if (now + this.oneDayMillis < exp * 1000) {
				throw this.error(
					"Assertion expires unreasonable far in the future",
					args("expired-at", new Date(exp * 1000), "now", new Date(now)),
				);
				//Arbitrary, allow for 1 day in the future as standard says "unreasonably far".
			}
		}

		const iat = env.getLong("client_assertion", "claims.iat");
		if (iat == null) {
			throw this.error("Missing iat");
		} else {
			if (now + this.oneDayMillis < iat * 1000) {
				// UPSTREAM: the message is copied from the exp check and the logged 'issued-at' value is taken from exp, not iat
				throw this.error(
					"Assertion expires unreasonable far in the future",
					args("issued-at", new Date(exp * 1000), "now", new Date(now)),
				);
				//Arbitrary, allow for 1 day in the future as standard says "unreasonably far".
			}
		}

		this.logSuccess("Client Assertion passed all validation checks");

		return env;
	}

	protected validateAud(env: Environment): void {
		const issuer = env.getString("server", "issuer");
		const tokenEndpoint = env.getString("server", "token_endpoint");
		if (!tokenEndpoint) {
			throw this.error(
				"Couldn't find issuer or client or token endpoint values in the test configuration to test the assertion",
			);
		}
		const mtlsTokenEndpoint = env.getString("server", "mtls_endpoint_aliases.token_endpoint");

		const aud = env.getElementFromObject("client_assertion", "claims.aud");
		if (aud === undefined) {
			throw this.error("Missing aud");
		}

		const tokenEndpoints: string[] = [tokenEndpoint];
		if (mtlsTokenEndpoint != null) {
			tokenEndpoints.push(mtlsTokenEndpoint);
		}

		if (isJsonArray(aud)) {
			// UPSTREAM: Java's new JsonPrimitive(mtlsTokenEndpoint) throws a NullPointerException when there is no
			// mtls_endpoint_aliases.token_endpoint and neither of the other values matched; here that is just "not found"
			if (
				!jsonArrayContains(aud, issuer as string) &&
				!jsonArrayContains(aud, tokenEndpoint) &&
				!(mtlsTokenEndpoint != null && jsonArrayContains(aud, mtlsTokenEndpoint))
			) {
				throw this.error("aud not found", args("expected", tokenEndpoints, "actual", aud));
			}
		} else {
			const audStr = OIDFJSON.getString(aud);
			if (audStr !== issuer && audStr !== tokenEndpoint && audStr !== mtlsTokenEndpoint) {
				throw this.error("aud mismatch", args("expected", tokenEndpoints, "actual", aud));
			}
		}
	}
}

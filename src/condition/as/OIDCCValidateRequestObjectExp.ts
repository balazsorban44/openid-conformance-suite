import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

/**
 * exp is optional, use with skipIfElementMissing
 */
export class OIDCCValidateRequestObjectExp extends AbstractCondition {
	private timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing

	static override pre: EnvironmentRequirements = { required: ["authorization_request_object"] };

	override evaluate(env: Environment): Environment {
		const now = Date.now(); // Instant, in epoch milliseconds

		const exp = env.getLong("authorization_request_object", "claims.exp");

		if (exp == null) {
			throw this.error("Missing exp, request object does not contain an 'exp' claim");
		}

		if (now - this.timeSkewMillis > exp * 1000) {
			throw this.error("Request object expired", args("exp", new Date(exp * 1000), "now", new Date(now)));
		}

		if (exp * 1000 > now + 50 * 365 * 24 * 60 * 60 * 1000) {
			throw this.error(
				"'exp' is unreasonably far in the future (more than 50 years), this may indicate the value was incorrectly specified in milliseconds instead of seconds",
				args("exp", new Date(exp * 1000), "now", new Date(now)),
			);
		}

		this.logSuccess("Request object contains a valid exp claim, expiry time", args("exp", new Date(exp * 1000)));

		return env;
	}
}

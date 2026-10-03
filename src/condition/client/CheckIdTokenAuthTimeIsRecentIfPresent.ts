import {
	AbstractCondition,
	args,
	has,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Equivalent of https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#auth_time_check
 */
export class CheckIdTokenAuthTimeIsRecentIfPresent extends AbstractCondition {
	private static readonly CLAIM_AUTH_TIME = "auth_time";

	private timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing

	static override pre: EnvironmentRequirements = { required: ["id_token"] };

	override evaluate(env: Environment): Environment {
		const CLAIM_AUTH_TIME = CheckIdTokenAuthTimeIsRecentIfPresent.CLAIM_AUTH_TIME;
		const idToken = (env.getObject("id_token") as JsonObject)["claims"] as JsonObject;

		if (has(idToken, CLAIM_AUTH_TIME)) {
			const authTime = OIDFJSON.getLong(idToken[CLAIM_AUTH_TIME]);

			// Instant.now().minusMillis(timeSkewMillis).minusSeconds(1).isAfter(Instant.ofEpochSecond(authTime))
			if (Date.now() - this.timeSkewMillis - 1000 > authTime * 1000) {
				throw this.error(
					"id_token auth_time is older than 1 second (allowing 5 minutes skews)",
					args("auth_time", new Date(authTime * 1000), "now", new Date()),
				);
			}

			// ValidateIdToken already checked if auth_time is in the future

			this.logSuccess(
				"auth_time in id_token is recent",
				args("auth_time", new Date(authTime * 1000), "now", new Date()),
			);
		} else {
			this.log("auth_time cannot be checked as it is missing from the id_token", args("id_token", idToken));
		}

		return env;
	}
}

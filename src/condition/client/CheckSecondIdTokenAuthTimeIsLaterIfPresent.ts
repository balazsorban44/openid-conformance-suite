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
 * Check auth_time changes when the user re-logins in due to prompt=login in the request
 *
 * Equivalent of https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#multiple_sign_on - but this version
 * checks that auth_time in the second id_token is newer, instead of just different as the python does.
 */
export class CheckSecondIdTokenAuthTimeIsLaterIfPresent extends AbstractCondition {
	private static readonly CLAIM_AUTH_TIME = "auth_time";

	static override pre: EnvironmentRequirements = { required: ["first_id_token", "id_token"] };

	override evaluate(env: Environment): Environment {
		const CLAIM_AUTH_TIME = CheckSecondIdTokenAuthTimeIsLaterIfPresent.CLAIM_AUTH_TIME;
		const firstIdToken = (env.getObject("first_id_token") as JsonObject)["claims"] as JsonObject;
		const secondIdToken = (env.getObject("id_token") as JsonObject)["claims"] as JsonObject;

		if (has(firstIdToken, CLAIM_AUTH_TIME) && has(secondIdToken, CLAIM_AUTH_TIME)) {
			const firstAuthTime = OIDFJSON.getLong(firstIdToken[CLAIM_AUTH_TIME]);
			const secondAuthTime = OIDFJSON.getLong(secondIdToken[CLAIM_AUTH_TIME]);

			if (firstAuthTime === secondAuthTime) {
				throw this.error(
					"prompt=login means the server was required to reauthenticate the user, the id_token from the second authorization incorrectly has the same auth_time as the id_token from the first authorization",
					args("first_id_token", firstIdToken, "second_id_token", secondIdToken),
				);
			}

			if (firstAuthTime > secondAuthTime) {
				throw this.error(
					"The id_token from the second authorization incorrectly has an earlier auth_time than the id_token from the first authorization",
					args("first_id_token", firstIdToken, "second_id_token", secondIdToken),
				);
			}

			this.logSuccess(
				"auth_time is later in the second id_token",
				args("first_id_token", firstIdToken, "second_id_token", secondIdToken),
			);
		} else {
			this.log(
				"auth_time cannot be checked as it is missing from the id_tokens for at least one of the authorizations",
				args("first_id_token", firstIdToken, "second_id_token", secondIdToken),
			);
		}

		return env;
	}
}

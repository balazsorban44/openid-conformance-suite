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
 * Check auth_time doesn't change for a prompt=none request
 *
 * Equivalent of (part of) https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#same_authn
 */
export class CheckIdTokenAuthTimeClaimsSameIfPresent extends AbstractCondition {
	private static readonly CLAIM_AUTH_TIME = "auth_time";

	static override pre: EnvironmentRequirements = { required: ["first_id_token", "id_token"] };

	override evaluate(env: Environment): Environment {
		const CLAIM_AUTH_TIME = CheckIdTokenAuthTimeClaimsSameIfPresent.CLAIM_AUTH_TIME;
		const firstIdToken = (env.getObject("first_id_token") as JsonObject)["claims"] as JsonObject;
		const secondIdToken = (env.getObject("id_token") as JsonObject)["claims"] as JsonObject;

		if (has(firstIdToken, CLAIM_AUTH_TIME) && has(secondIdToken, CLAIM_AUTH_TIME)) {
			const firstAuthTime = OIDFJSON.getLong(firstIdToken[CLAIM_AUTH_TIME]);
			const authTime = OIDFJSON.getLong(secondIdToken[CLAIM_AUTH_TIME]);

			if (firstAuthTime !== authTime) {
				throw this.error(
					"The id_tokens contain different auth_time claims, but must contain the same auth_time.",
					args("first_id_token", firstIdToken, "second_id_token", secondIdToken),
				);
			}

			this.logSuccess(
				"auth_time is the same in the second id_token",
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

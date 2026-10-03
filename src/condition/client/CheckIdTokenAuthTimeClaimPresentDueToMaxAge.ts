import {
	AbstractCondition,
	args,
	has,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Equivalent of https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-Req-max_age=1.json#L66
 */
export class CheckIdTokenAuthTimeClaimPresentDueToMaxAge extends AbstractCondition {
	private static readonly CLAIM_AUTH_TIME = "auth_time";

	static override pre: EnvironmentRequirements = { required: ["id_token"] };

	override evaluate(env: Environment): Environment {
		const idToken = (env.getObject("id_token") as JsonObject)["claims"] as JsonObject;

		if (!has(idToken, CheckIdTokenAuthTimeClaimPresentDueToMaxAge.CLAIM_AUTH_TIME)) {
			throw this.error(
				"auth_time claim is missing from the id_token, but it is required for a authentication where the max_age parameter was used",
				args("id_token", idToken),
			);
		}

		// no need to check type as ValidateIdToken did so
		this.logSuccess(
			"auth_time is present in the id_token, as required for a authentication where the max_age parameter was used",
			args("id_token", idToken),
		);

		return env;
	}
}

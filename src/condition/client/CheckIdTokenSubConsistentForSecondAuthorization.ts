import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Check sub doesn't change for a prompt=none request
 *
 * Equivalent of (part of) https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#same_authn
 */
export class CheckIdTokenSubConsistentForSecondAuthorization extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["first_id_token", "id_token"] };

	override evaluate(env: Environment): Environment {
		const firstIdToken = (env.getObject("first_id_token") as JsonObject)["claims"] as JsonObject;
		const secondIdToken = (env.getObject("id_token") as JsonObject)["claims"] as JsonObject;

		const subFirst = env.getString("first_id_token", "claims.sub");

		const subSecond = env.getString("id_token", "claims.sub");

		// UPSTREAM: Java's subFirst.equals(...) throws a NullPointerException when the first id_token has no sub
		if (subFirst !== subSecond) {
			throw this.error(
				"The id_token from the first and second authorization contain different sub claims, but must contain the same sub.",
				args("first_id_token", firstIdToken, "second_id_token", secondIdToken),
			);
		}

		this.logSuccess(
			"sub is the same in the second id_token",
			args("first_id_token", firstIdToken, "second_id_token", secondIdToken),
		);

		return env;
	}
}

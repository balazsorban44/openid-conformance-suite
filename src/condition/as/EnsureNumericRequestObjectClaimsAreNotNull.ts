import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

/**
 * This condition should only be used to log WARNINGs and should not result in failures
 */
export class EnsureNumericRequestObjectClaimsAreNotNull extends AbstractCondition {
	/**
	 * Names of numeric claims
	 * Also used by CreateEffectiveAuthorizationRequestParameters
	 */
	static readonly numericClaimNames: Set<string> = new Set(["max_age"]);

	static override pre: EnvironmentRequirements = { required: ["authorization_request_object"] };

	override evaluate(env: Environment): Environment {
		const argsForLog: Record<string, unknown> = {};

		for (const claimName of EnsureNumericRequestObjectClaimsAreNotNull.numericClaimNames) {
			const jsonElement = env.getElementFromObject("authorization_request_object", "claims." + claimName);
			if (jsonElement !== undefined && jsonElement === null) {
				argsForLog[claimName] = "Should have a numeric value.";
			}
		}
		if (Object.keys(argsForLog).length > 0) {
			throw this.error(
				"Request object contains null value(s) for claim(s) that are expected to have numeric values." +
					" This is allowed but not recommended.",
				args("claims", argsForLog),
			);
		}
		this.logSuccess(
			"None of the claims expected to have numeric values, have null values",
			args("numeric_claims", [...EnsureNumericRequestObjectClaimsAreNotNull.numericClaimNames]),
		);
		return env;
	}
}

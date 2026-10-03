import {
	AbstractCondition,
	args,
	isJsonObject,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class CheckRequestClaimsParameterValues extends AbstractCondition {
	// https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
	private static readonly expectedTopLevelClaims: string[] = ["userinfo", "id_token"];

	static override pre: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		const invalidClaims: string[] = [];
		const validClaims: string[] = [];

		// UPSTREAM: Java calls getAsJsonObject() on a possibly missing element (NullPointerException) before the null check below
		const claimsParameter = env.getElementFromObject(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			"claims",
		) as JsonObject;

		if (claimsParameter == null || Object.keys(claimsParameter).length === 0) {
			this.logSuccess("authorization request 'claims' parameter does not exist or is empty");
			return env;
		}

		for (const claim of Object.keys(claimsParameter)) {
			// Ignore unexpected claims
			if (!CheckRequestClaimsParameterValues.expectedTopLevelClaims.includes(claim)) {
				continue;
			}

			const claimObject = claimsParameter[claim];

			if (isJsonObject(claimObject)) {
				validClaims.push(claim);
			} else {
				invalidClaims.push(claim);
			}
		}

		if (invalidClaims.length === 0) {
			this.logSuccess(
				"the expected authorization request 'claims' parameter claims values are json objects",
				args("valid_claims", validClaims),
			);
		} else {
			throw this.error(
				"the expected authorization request 'claims' parameter claims values are not json objects",
				args("valid_claims", validClaims, "invalid_claims", invalidClaims),
			);
		}

		return env;
	}
}

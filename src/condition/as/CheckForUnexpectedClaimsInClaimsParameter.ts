import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class CheckForUnexpectedClaimsInClaimsParameter extends AbstractCondition {
	static expectedClaims: string[] = [
		// as per https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
		"userinfo",
		"id_token",
	];

	protected getExpectedClaims(): string[] {
		return CheckForUnexpectedClaimsInClaimsParameter.expectedClaims;
	}

	static override pre: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		// UPSTREAM: Java calls getAsJsonObject() on a possibly missing element (NullPointerException) before the null check below
		const claimsParameter = env.getElementFromObject(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			"claims",
		) as JsonObject;
		const unknownClaims: string[] = [];

		if (claimsParameter == null || Object.keys(claimsParameter).length === 0) {
			this.logSuccess("authorization request 'claims' parameter does not exist or is empty");
			return env;
		}

		for (const claim of Object.keys(claimsParameter)) {
			if (this.getExpectedClaims().includes(claim)) {
				continue;
			}

			unknownClaims.push(claim);
		}

		if (unknownClaims.length === 0) {
			this.logSuccess(
				"authorization request 'claims' parameter contains only expected claims",
				args("claims", Object.keys(claimsParameter)),
			);
		} else {
			throw this.error(
				"unknown claims found in authorization request 'claims' parameter",
				args("claims", Object.keys(claimsParameter), "unknown_claims", unknownClaims),
			);
		}

		return env;
	}
}

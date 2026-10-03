import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
} from "../../framework/index.ts";

export class ValidateIdTokenACRClaimAgainstRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token", "authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		// Read what the server has sent us
		const idTokenAcrClaim = env.getElementFromObject("id_token", "claims.acr");

		// Do validation; regardless of what we requested if an acr is returned it must be a string
		if (idTokenAcrClaim != null) {
			if (typeof idTokenAcrClaim !== "string") {
				throw this.error("acr value in id_token must be a string", args("id_token", env.getObject("id_token")));
			}
		}

		const requestedAcrValue = env.getElementFromObject("authorization_endpoint_request", "claims.id_token.acr.value");
		const requestedAcrValues = env.getElementFromObject("authorization_endpoint_request", "claims.id_token.acr.values");
		const requestedValues: string[] = [];
		if (requestedAcrValues != null) {
			for (const value of requestedAcrValues as JsonArray) {
				const val = OIDFJSON.getString(value);
				requestedValues.push(val);
			}
		} else if (requestedAcrValue != null) {
			requestedValues.push(OIDFJSON.getString(requestedAcrValue));
		} else {
			this.logSuccess("Nothing to check; the conformance suite did not request an acr claim in request object");
			return env;
		}

		if (idTokenAcrClaim == null) {
			throw this.error(
				"One or more acr values were requested as an 'essential: true' claim so, as the authentication succeeded, the acr used MUST be returned in the id_token",
				args("id_token", env.getObject("id_token"), "expected", requestedValues),
			);
		}

		const idTokenValue = OIDFJSON.getString(idTokenAcrClaim);

		for (const singleAcrValue of requestedValues) {
			if (idTokenValue === singleAcrValue) {
				this.logSuccess(
					"acr value in id_token is (one of) the requested values",
					args("requested", requestedValues, "actual", idTokenValue),
				);
				return env;
			}
		}

		throw this.error(
			"acr value in id_token is not (one of the) requested values",
			args("requested", requestedValues, "actual", idTokenValue),
		);
	}
}

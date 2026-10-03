import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class ValidateIdTokenACRClaimAgainstAcrValuesRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token", "authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		// Read what the server has sent us
		const idTokenAcrClaim = env.getElementFromObject("id_token", "claims.acr");

		const requestedAcrValues = env.getElementFromObject("authorization_endpoint_request", "acr_values");
		if (requestedAcrValues == null) {
			throw this.error(
				"authorization endpoint request did not contain acr_values; this is a problem with the conformance suite",
			);
		}

		if (idTokenAcrClaim == null) {
			throw this.error(
				"An acr value was requested using acr_values, so the server 'SHOULD' return an acr claim, but it did not.",
				args("request", env.getObject("authorization_endpoint_request"), "id_token", env.getObject("id_token")),
			);
		}

		if (typeof idTokenAcrClaim !== "string") {
			throw this.error("acr value in id_token must be a string", args("id_token", env.getObject("id_token")));
		}

		const idTokenAcr = OIDFJSON.getString(idTokenAcrClaim);

		const requestedValues = OIDFJSON.getString(requestedAcrValues).split(" ");

		if (requestedValues.includes(idTokenAcr)) {
			this.logSuccess(
				"id_token acr claim contains one of the requested values",
				args("requested_values", requestedValues, "id_token_acr", idTokenAcr),
			);
			return env;
		}

		throw this.error(
			"acr value in id_token is not (one of the) requested values",
			args("requested_values", requestedValues, "id_token_acr", idTokenAcr),
		);
	}
}

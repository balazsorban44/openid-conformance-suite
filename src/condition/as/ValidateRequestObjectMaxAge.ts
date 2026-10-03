import {
	AbstractCondition,
	args,
	OIDFJSON,
	UnexpectedJsonTypeException,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class ValidateRequestObjectMaxAge extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_request_object"] };

	override evaluate(env: Environment): Environment {
		//Also see CreateEffectiveAuthorizationRequestParameters for max_age processing
		const maxAgeElement = env.getElementFromObject("authorization_request_object", "claims.max_age");
		if (maxAgeElement === undefined) {
			this.log("Request object does not contain a max_age claim");
			return env;
		} else if (maxAgeElement === null) {
			//EnsureNumericRequestObjectClaimsAreNotNull handles the JsonNull case
			//Additionally, CreateEffectiveAuthorizationRequestParameters completely ignores max_age when it is json null
			this.log("max_age has a 'json null' value");
			return env;
		} else {
			let maxAge: number;
			try {
				maxAge = OIDFJSON.getNumber(maxAgeElement);
			} catch (ex) {
				if (ex instanceof UnexpectedJsonTypeException) {
					throw this.error("max_age is not encoded as a number", args("max_age", maxAgeElement));
				}
				throw ex;
			}
			this.logSuccess("max_age is correctly encoded as a number", args("max_age", maxAge));
			return env;
		}
	}
}

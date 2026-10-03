import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureClientAssertionTypeIsJwt extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const assertionType = env.getString("token_endpoint_request", "body_form_params.client_assertion_type");

		const expected = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

		if (expected === assertionType) {
			this.logSuccess("Found JWT assertion type", args("assertion type", expected));
			return env;
		} else if (assertionType == null) {
			throw this.error(
				"client_assertion_type missing from request parameters",
				args("expected", expected, "actual", null),
			);
		} else {
			throw this.error("client_assertion_type does not match JWT", args("expected", expected, "actual", assertionType));
		}
	}
}

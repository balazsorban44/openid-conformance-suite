import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ValidateAuthorizationCode extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		strings: ["authorization_code"],
		required: ["token_endpoint_request"],
	};

	override evaluate(env: Environment): Environment {
		const expected = env.getString("authorization_code");
		const actual = env.getString("token_endpoint_request", "body_form_params.code");

		if (!expected) {
			throw this.error("Couldn't find authorization code to compare");
		}

		if (expected === actual) {
			this.logSuccess("Found authorization code", args("authorization_code", actual));
			return env;
		} else {
			throw this.error("Didn't find matching authorization code", args("expected", expected, "actual", actual));
		}
	}
}

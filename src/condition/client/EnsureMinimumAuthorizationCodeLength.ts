import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureMinimumAuthorizationCodeLength extends AbstractCondition {
	private readonly requiredLength = 128;

	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const authorizationCode = env.getString("authorization_endpoint_response", "code");

		if (!authorizationCode) {
			throw this.error("Can't find authorization code");
		}

		const bytes = Buffer.from(authorizationCode, "utf8");
		const bitLength = bytes.length * 8;

		if (bitLength >= this.requiredLength) {
			this.logSuccess(
				"Authorization code is of sufficient length",
				args("required", this.requiredLength, "actual", bitLength),
			);
			return env;
		} else {
			throw this.error(
				"Authorization code is not long enough",
				args("required_bits", this.requiredLength, "actual_bits", bitLength),
			);
		}
	}
}

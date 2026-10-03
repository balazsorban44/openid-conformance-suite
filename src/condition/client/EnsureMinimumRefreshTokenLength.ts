import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureMinimumRefreshTokenLength extends AbstractCondition {
	private readonly requiredLength = 128;

	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const refreshToken = env.getString("token_endpoint_response", "refresh_token");

		if (!refreshToken) {
			throw this.error("Can't find refresh token");
		}

		const bytes = Buffer.from(refreshToken, "utf8");
		const bitLength = bytes.length * 8;

		if (bitLength >= this.requiredLength) {
			this.logSuccess(
				"Refresh token is of sufficient length",
				args("required", this.requiredLength, "actual", bitLength),
			);
			return env;
		} else {
			throw this.error(
				"Refresh token is not of sufficient length",
				args("required", this.requiredLength, "actual", bitLength),
			);
		}
	}
}

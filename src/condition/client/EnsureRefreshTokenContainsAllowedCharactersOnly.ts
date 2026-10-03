import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureRefreshTokenContainsAllowedCharactersOnly extends AbstractCondition {
	private static readonly VSCHAR_PATTERN = "[\\x20-\\x7E]+";

	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const refreshToken = env.getString("token_endpoint_response", "refresh_token");
		if (refreshToken == null) {
			this.logSuccess("Token endpoint response does not contain a refresh_token");
			return env;
		}

		const validPattern = new RegExp("^(?:" + EnsureRefreshTokenContainsAllowedCharactersOnly.VSCHAR_PATTERN + ")$");
		if (!validPattern.test(refreshToken)) {
			throw this.error(
				"Refresh token contains illegal characters. As per RFC-6749, only characters between %x20 and %x7E are allowed.",
				args("refresh_token", refreshToken),
			);
		}

		this.logSuccess("Refresh token does not contain any illegal characters");

		return env;
	}
}

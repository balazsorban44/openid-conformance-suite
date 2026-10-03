import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureAccessTokenContainsAllowedCharactersOnly extends AbstractCondition {
	private static readonly VSCHAR_PATTERN = "[\\x20-\\x7E]+";

	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const accessToken = env.getString("token_endpoint_response", "access_token");
		if (accessToken == null) {
			throw this.error("Token endpoint response does not contain an access_token");
		}

		const validPattern = new RegExp("^(?:" + EnsureAccessTokenContainsAllowedCharactersOnly.VSCHAR_PATTERN + ")$");
		if (!validPattern.test(accessToken)) {
			throw this.error(
				"Access token contains illegal characters. As per RFC-6749, only characters between %x20 and %x7E are allowed.",
				args("access_token", accessToken),
			);
		}

		this.logSuccess("Access token does not contain any illegal characters");

		return env;
	}
}

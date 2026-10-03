import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ValidateErrorFromTokenEndpointResponseError extends AbstractCondition {
	private static readonly ERROR_FIELD_PATTERN_VALID = "[\\x20-\\x21\\x23-\\x5B\\x5D-\\x7E]+";

	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const error = env.getString("token_endpoint_response", "error");
		if (!error) {
			throw this.error(
				"The authorization server was expected to return an error, but the 'error' field in the response is either null or empty",
			);
		}
		if (!this.isValidErrorFieldFormat(error)) {
			throw this.error(
				"'error' field MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E",
				args("error", error),
			);
		}
		this.logSuccess("Token endpoint response error returned valid 'error' field", args("error", error));
		return env;
	}

	private isValidErrorFieldFormat(str: string): boolean {
		const validPattern = new RegExp(
			"^(?:" + ValidateErrorFromTokenEndpointResponseError.ERROR_FIELD_PATTERN_VALID + ")$",
		);
		if (validPattern.test(str)) {
			return true;
		}
		return false;
	}
}

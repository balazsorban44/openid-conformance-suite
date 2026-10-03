import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export abstract class AbstractValidateErrorDescriptionFromResponseError extends AbstractCondition {
	private static readonly ERROR_DESCRIPTION_FIELD_PATTERN_VALID = "[\\x09\\x0A\\x0D\\x20-\\x21\\x23-\\x5B\\x5D-\\x7E]+";

	protected validateErrorDescription(env: Environment, endpointResponseKey: string): Environment {
		const errorDescription = env.getString(endpointResponseKey, "error_description");

		if (!errorDescription) {
			this.logSuccess(endpointResponseKey + " did not include optional 'error_description' field");
			return env;
		}
		if (!this.isValidErrorDescriptionFieldFormat(errorDescription)) {
			throw this.error(
				"'error_description' field MUST NOT include characters outside the set %09-0A (Tab and LF) / %x0D (CR) / %x20-21 / %x23-5B / %x5D-7E",
				args("error_description", errorDescription),
			);
		}
		this.logSuccess(
			endpointResponseKey + " error returned valid 'error_description' field",
			args("error_description", errorDescription),
		);
		return env;
	}

	private isValidErrorDescriptionFieldFormat(str: string): boolean {
		const validPattern = new RegExp(
			"^(?:" + AbstractValidateErrorDescriptionFromResponseError.ERROR_DESCRIPTION_FIELD_PATTERN_VALID + ")$",
		);
		if (validPattern.test(str)) {
			return true;
		}
		return false;
	}
}

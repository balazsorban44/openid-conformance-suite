import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export abstract class AbstractCheckErrorDescriptionContainsCRLFTAB extends AbstractCondition {
	protected checkExistCRLFTAB(env: Environment, endpointResponseKey: string): Environment {
		const errorDescription = env.getString(endpointResponseKey, "error_description");

		if (!errorDescription) {
			this.logSuccess(endpointResponseKey + " did not include optional 'error_description' field");
			return env;
		}
		if (this.isExistCRLFTAB(errorDescription)) {
			throw this.error(
				"'error_description' field includes characters CR, LF or TAB, these are not recommended to include",
				args(
					"error_description",
					errorDescription,
					"see",
					"https://bitbucket.org/openid/connect/issues/1147/certification-rfc6749-must-for",
				),
			);
		}
		this.logSuccess(
			endpointResponseKey + " 'error_description' field does not include CR/LF/TAB",
			args("error_description", errorDescription),
		);
		return env;
	}

	private isExistCRLFTAB(str: string): boolean {
		if (str.includes("\n") || str.includes("\r") || str.includes("\t")) {
			return true;
		}
		return false;
	}
}

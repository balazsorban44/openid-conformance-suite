import { AbstractCondition, args, isJsonPrimitive, OIDFJSON, type Environment } from "../../framework/index.ts";

export abstract class AbstractValidateJsonBoolean extends AbstractCondition {
	validate(env: Environment, environmentVariable: string, defaultValue: boolean, requiredValue: boolean): Environment {
		const parameterValue = env.getElementFromObject("server", environmentVariable);
		let errorMessage: string | null = null;

		if (parameterValue === undefined) {
			if (defaultValue !== requiredValue) {
				errorMessage =
					"'" +
					environmentVariable +
					"' should be '" +
					requiredValue +
					"', but is absent and the default value is '" +
					defaultValue +
					"'.";
			}
		} else {
			if (isJsonPrimitive(parameterValue)) {
				if (typeof parameterValue !== "boolean") {
					errorMessage = environmentVariable + ": incorrect type, must be a boolean.";
				} else if (OIDFJSON.getBoolean(parameterValue) !== requiredValue) {
					errorMessage = environmentVariable + " must be: " + requiredValue;
				}
			} else {
				errorMessage = environmentVariable + ": incorrect type, must be a boolean.";
			}
		}

		if (errorMessage != null) {
			throw this.error(
				errorMessage,
				args(
					"discovery_metadata_key",
					environmentVariable,
					"expected",
					requiredValue,
					"actual",
					parameterValue ?? null,
				),
			);
		}

		this.logSuccess(environmentVariable + " has correct value", args(environmentVariable, parameterValue ?? null));

		return env;
	}
}

import {
	AbstractCondition,
	args,
	isJsonArray,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class OIDCCCheckDiscEndpointGrantTypesSupported extends AbstractCondition {
	private static readonly environmentVariable = "grant_types_supported";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const environmentVariable = OIDCCCheckDiscEndpointGrantTypesSupported.environmentVariable;
		const grantTypesSupported = env.getElementFromObject("server", environmentVariable);
		if (grantTypesSupported != null) {
			if (!isJsonArray(grantTypesSupported)) {
				throw this.error(
					environmentVariable + " in discovery document, if present, must be an array.",
					args(environmentVariable, grantTypesSupported),
				);
			}
			const a = grantTypesSupported;
			if (a.length === 0) {
				throw this.error(environmentVariable + " in discovery document must not be an empty array.");
			}
			this.logSuccess(environmentVariable + " is a non-empty array.", args(environmentVariable, grantTypesSupported));
		} else {
			this.logSuccess(
				environmentVariable +
					" not present in server configuration (so will default to authorization_code and implicit).",
			);
		}

		return env;
	}
}

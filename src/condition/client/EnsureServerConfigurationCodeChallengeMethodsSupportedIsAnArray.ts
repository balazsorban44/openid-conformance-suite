import { isJsonArray, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class EnsureServerConfigurationCodeChallengeMethodsSupportedIsAnArray extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "code_challenge_methods_supported";
	private static readonly SET_VALUES: string[] = ["S256", "plain"];
	private static readonly errorMessageNotEnough = "No matching value from server";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const environmentVariable = EnsureServerConfigurationCodeChallengeMethodsSupportedIsAnArray.environmentVariable;
		const serverValues = env.getElementFromObject("server", environmentVariable);

		// For OIDC there is no requirement to support PKCE. Thus a missing claim or a claim
		// with an empty array value is valid.
		if (serverValues === undefined) {
			this.logSuccess(environmentVariable + " is not present in the discovery document");
			return env;
		} else if (isJsonArray(serverValues) && serverValues.length === 0) {
			this.logSuccess(environmentVariable + " is an empty array");
			return env;
		}

		// Ensure the value as an array and contains a valid entry.
		return this.validate(
			env,
			environmentVariable,
			EnsureServerConfigurationCodeChallengeMethodsSupportedIsAnArray.SET_VALUES,
			1,
			EnsureServerConfigurationCodeChallengeMethodsSupportedIsAnArray.errorMessageNotEnough,
		);
	}
}

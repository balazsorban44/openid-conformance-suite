import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256 extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "userinfo_signing_alg_values_supported";
	private static readonly SET_VALUES: string[] = ["RS256"];
	private static readonly minimumMatchesRequired = 1;
	private static readonly errorMessageNotEnough: string | null =
		"RS256 is not listed in userinfo_signing_alg_values_supported";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256.environmentVariable,
			CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256.SET_VALUES,
			CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256.minimumMatchesRequired,
			CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256.errorMessageNotEnough,
		);
	}
}

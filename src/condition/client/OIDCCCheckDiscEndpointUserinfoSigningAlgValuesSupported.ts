import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "userinfo_signing_alg_values_supported";
	private static readonly SET_VALUES: string[] = [];
	private static readonly minimumMatchesRequired =
		OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported.SET_VALUES.length;
	// There are no required values in this case ("none" MAY be included), so the "not enough"
	// message will never be used. We do make use of the checks for being an array.
	private static readonly errorMessageNotEnough: string | null = null;

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported.environmentVariable,
			OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported.SET_VALUES,
			OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported.minimumMatchesRequired,
			OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported.errorMessageNotEnough,
		);
	}
}

import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class OIDCCCheckDiscEndpointClaimsSupported extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "claims_supported";
	private static readonly SET_VALUES: string[] = [];
	private static readonly minimumMatchesRequired = OIDCCCheckDiscEndpointClaimsSupported.SET_VALUES.length;
	// There are no required values in this case ("none" MAY be included), so the "not enough"
	// message will never be used. We do make use of the checks for being an array.
	private static readonly errorMessageNotEnough: string | null = null;

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			OIDCCCheckDiscEndpointClaimsSupported.environmentVariable,
			OIDCCCheckDiscEndpointClaimsSupported.SET_VALUES,
			OIDCCCheckDiscEndpointClaimsSupported.minimumMatchesRequired,
			OIDCCCheckDiscEndpointClaimsSupported.errorMessageNotEnough,
		);
	}
}

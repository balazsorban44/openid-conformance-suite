import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "id_token_signing_alg_values_supported";
	private static readonly SET_VALUES: string[] = ["RS256"];
	private static readonly minimumMatchesRequired =
		OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported.SET_VALUES.length;
	private static readonly errorMessageNotEnough: string | null =
		"RS256 support is required, but the server does not list it in id_token_signing_alg_values_supported";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported.environmentVariable,
			OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported.SET_VALUES,
			OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported.minimumMatchesRequired,
			OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported.errorMessageNotEnough,
		);
	}
}

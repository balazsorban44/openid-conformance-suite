import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class CheckDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256 extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "request_object_signing_alg_values_supported";
	private static readonly SET_VALUES: string[] = ["RS256"];
	private static readonly minimumMatchesRequired = 1;
	private static readonly errorMessageNotEnough: string | null =
		"Discovery endpoint request_object_signing_alg_values_supported does not include RS256.";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			CheckDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256.environmentVariable,
			CheckDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256.SET_VALUES,
			CheckDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256.minimumMatchesRequired,
			CheckDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256.errorMessageNotEnough,
		);
	}
}

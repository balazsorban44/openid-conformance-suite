import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class CheckDiscEndpointSubjectTypesSupported extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "subject_types_supported";
	private static readonly SET_VALUES: string[] = ["public", "pairwise"];
	private static readonly minimumMatchesRequired = 1;
	private static readonly errorMessageNotEnough =
		CheckDiscEndpointSubjectTypesSupported.environmentVariable +
		" is required to contain at least one of public or pairwise";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			CheckDiscEndpointSubjectTypesSupported.environmentVariable,
			CheckDiscEndpointSubjectTypesSupported.SET_VALUES,
			CheckDiscEndpointSubjectTypesSupported.minimumMatchesRequired,
			CheckDiscEndpointSubjectTypesSupported.errorMessageNotEnough,
		);
	}
}

import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateResponseTypesArray } from "./AbstractValidateResponseTypesArray.ts";

export class OIDCCCheckDiscEndpointResponseTypesSupported extends AbstractValidateResponseTypesArray {
	private static readonly environmentVariable = "response_types_supported";
	private static readonly SET_VALUES: string[] = [
		"code",
		"code id_token",
		"id_token",
		"token id_token",
		"code id_token token",
		"code token",
	];
	private static readonly minimumMatchesRequired = 1;
	private static readonly errorMessageNotEnough: string | null =
		"The server must support at least one of the response types defined in OpenID Connect.";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			OIDCCCheckDiscEndpointResponseTypesSupported.environmentVariable,
			OIDCCCheckDiscEndpointResponseTypesSupported.SET_VALUES,
			OIDCCCheckDiscEndpointResponseTypesSupported.minimumMatchesRequired,
			OIDCCCheckDiscEndpointResponseTypesSupported.errorMessageNotEnough,
		);
	}
}

import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateResponseTypesArray } from "./AbstractValidateResponseTypesArray.ts";

export class OIDCCCheckDiscEndpointResponseTypesSupportedDynamic extends AbstractValidateResponseTypesArray {
	private static readonly environmentVariable = "response_types_supported";
	private static readonly SET_VALUES: string[] = ["code", "id_token", "token id_token"];
	private static readonly minimumMatchesRequired =
		OIDCCCheckDiscEndpointResponseTypesSupportedDynamic.SET_VALUES.length;
	private static readonly errorMessageNotEnough: string | null =
		"The server does not support all of the mandatory to implement response_types for dynamic OpenID Providers.";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			OIDCCCheckDiscEndpointResponseTypesSupportedDynamic.environmentVariable,
			OIDCCCheckDiscEndpointResponseTypesSupportedDynamic.SET_VALUES,
			OIDCCCheckDiscEndpointResponseTypesSupportedDynamic.minimumMatchesRequired,
			OIDCCCheckDiscEndpointResponseTypesSupportedDynamic.errorMessageNotEnough,
		);
	}
}

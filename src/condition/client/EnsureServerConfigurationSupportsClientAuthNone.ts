import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class EnsureServerConfigurationSupportsClientAuthNone extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "token_endpoint_auth_methods_supported";
	private static readonly SET_VALUES: string[] = ["none"];
	private static readonly minimumMatchesRequired = 1;
	private static readonly errorMessageNotEnough: string | null =
		"server discovery document does not contain none in token_endpoint_auth_methods_supported";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			EnsureServerConfigurationSupportsClientAuthNone.environmentVariable,
			EnsureServerConfigurationSupportsClientAuthNone.SET_VALUES,
			EnsureServerConfigurationSupportsClientAuthNone.minimumMatchesRequired,
			EnsureServerConfigurationSupportsClientAuthNone.errorMessageNotEnough,
		);
	}
}

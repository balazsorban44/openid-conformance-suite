import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class EnsureServerConfigurationSupportsClientSecretPost extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "token_endpoint_auth_methods_supported";
	private static readonly SET_VALUES: string[] = ["client_secret_post"];
	private static readonly minimumMatchesRequired = 1;
	private static readonly errorMessageNotEnough: string | null =
		"server discovery document does not contain client_secret_post in token_endpoint_auth_methods_supported";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			EnsureServerConfigurationSupportsClientSecretPost.environmentVariable,
			EnsureServerConfigurationSupportsClientSecretPost.SET_VALUES,
			EnsureServerConfigurationSupportsClientSecretPost.minimumMatchesRequired,
			EnsureServerConfigurationSupportsClientSecretPost.errorMessageNotEnough,
		);
	}
}

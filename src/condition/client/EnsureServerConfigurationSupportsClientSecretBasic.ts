import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class EnsureServerConfigurationSupportsClientSecretBasic extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "token_endpoint_auth_methods_supported";
	private static readonly SET_VALUES: string[] = ["client_secret_basic"];
	private static readonly errorMessageNotEnough =
		"server discovery document contains token_endpoint_auth_methods_supported which does not contain client_secret_basic";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const supportedAuthMethods = env.getElementFromObject("server", "token_endpoint_auth_methods_supported");

		if (supportedAuthMethods === undefined) {
			this.logSuccess(
				"server discovery document does not contain token_endpoint_auth_methods_supported, so by default client_secret_basic support is supported",
			);
			return env;
		}

		return this.validate(
			env,
			EnsureServerConfigurationSupportsClientSecretBasic.environmentVariable,
			EnsureServerConfigurationSupportsClientSecretBasic.SET_VALUES,
			1,
			EnsureServerConfigurationSupportsClientSecretBasic.errorMessageNotEnough,
		);
	}
}

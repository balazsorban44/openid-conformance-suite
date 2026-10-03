import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class CheckDiscEndpointScopesSupportedContainsOpenId extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "scopes_supported";
	private static readonly SET_VALUES: string[] = ["openid"];
	private static readonly minimumMatchesRequired = 1;
	private static readonly errorMessageNotEnough: string | null =
		"scopes_supported in the server's discovery document does not contain 'openid'.";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			CheckDiscEndpointScopesSupportedContainsOpenId.environmentVariable,
			CheckDiscEndpointScopesSupportedContainsOpenId.SET_VALUES,
			CheckDiscEndpointScopesSupportedContainsOpenId.minimumMatchesRequired,
			CheckDiscEndpointScopesSupportedContainsOpenId.errorMessageNotEnough,
		);
	}
}

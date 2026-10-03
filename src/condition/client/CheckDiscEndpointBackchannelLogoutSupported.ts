import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonBoolean } from "./AbstractValidateJsonBoolean.ts";

export class CheckDiscEndpointBackchannelLogoutSupported extends AbstractValidateJsonBoolean {
	private static readonly environmentVariable = "backchannel_logout_supported";
	private static readonly requiredValue = true;
	private static readonly defaultValue = false;

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			CheckDiscEndpointBackchannelLogoutSupported.environmentVariable,
			CheckDiscEndpointBackchannelLogoutSupported.defaultValue,
			CheckDiscEndpointBackchannelLogoutSupported.requiredValue,
		);
	}
}

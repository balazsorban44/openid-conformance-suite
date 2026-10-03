import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonBoolean } from "./AbstractValidateJsonBoolean.ts";

export class CheckDiscEndpointFrontchannelLogoutSessionSupported extends AbstractValidateJsonBoolean {
	private static readonly environmentVariable = "frontchannel_logout_session_supported";
	private static readonly requiredValue = true;
	private static readonly defaultValue = false;

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			CheckDiscEndpointFrontchannelLogoutSessionSupported.environmentVariable,
			CheckDiscEndpointFrontchannelLogoutSessionSupported.defaultValue,
			CheckDiscEndpointFrontchannelLogoutSessionSupported.requiredValue,
		);
	}
}

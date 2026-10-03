import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonBoolean } from "./AbstractValidateJsonBoolean.ts";

export class CheckDiscEndpointRequestUriParameterSupported extends AbstractValidateJsonBoolean {
	private static readonly environmentVariable = "request_uri_parameter_supported";
	private static readonly requiredValue = true;
	private static readonly defaultValue = true;

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			CheckDiscEndpointRequestUriParameterSupported.environmentVariable,
			CheckDiscEndpointRequestUriParameterSupported.defaultValue,
			CheckDiscEndpointRequestUriParameterSupported.requiredValue,
		);
	}
}

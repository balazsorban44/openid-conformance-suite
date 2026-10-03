import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonBoolean } from "./AbstractValidateJsonBoolean.ts";

export class CheckDiscEndpointClaimsParameterSupported extends AbstractValidateJsonBoolean {
	private static readonly environmentVariable = "claims_parameter_supported";
	private static readonly requiredValue = true;
	private static readonly defaultValue = false;

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			CheckDiscEndpointClaimsParameterSupported.environmentVariable,
			CheckDiscEndpointClaimsParameterSupported.defaultValue,
			CheckDiscEndpointClaimsParameterSupported.requiredValue,
		);
	}
}

import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class OIDCCCheckDiscEndpointGrantTypesSupportedDynamic extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "grant_types_supported";
	private static readonly SET_VALUES: string[] = ["authorization_code", "implicit"];
	private static readonly minimumMatchesRequired = OIDCCCheckDiscEndpointGrantTypesSupportedDynamic.SET_VALUES.length;
	private static readonly errorMessageNotEnough =
		"Servers certifying for the 'dynamic' certification profile are required to support the grant types 'authorization_code' and 'implicit'.";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const environmentVariable = OIDCCCheckDiscEndpointGrantTypesSupportedDynamic.environmentVariable;
		const grantTypesSupported = env.getElementFromObject("server", environmentVariable);

		if (grantTypesSupported === undefined) {
			this.logSuccess(
				"server discovery document does not contain " +
					environmentVariable +
					", so by default authorization_code and implicit are supported",
			);
			return env;
		}

		return this.validate(
			env,
			environmentVariable,
			OIDCCCheckDiscEndpointGrantTypesSupportedDynamic.SET_VALUES,
			OIDCCCheckDiscEndpointGrantTypesSupportedDynamic.minimumMatchesRequired,
			OIDCCCheckDiscEndpointGrantTypesSupportedDynamic.errorMessageNotEnough,
		);
	}
}

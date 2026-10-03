import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export class CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256 extends AbstractValidateJsonArray {
	private static readonly environmentVariable = "request_object_signing_alg_values_supported";
	private static readonly SET_VALUES: string[] = ["RS256"];
	private static readonly minimumMatchesRequired =
		CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256.SET_VALUES.length;
	private static readonly errorMessageNotEnough: string | null =
		"The server does not support RS256; this is a 'should' in https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata - note that support for 'none' (unsigned request objects) is not required as use of this is discouraged in many circumstances, see https://gitlab.com/openid/conformance-suite/-/issues/826";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(
			env,
			CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256.environmentVariable,
			CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256.SET_VALUES,
			CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256.minimumMatchesRequired,
			CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256.errorMessageNotEnough,
		);
	}
}

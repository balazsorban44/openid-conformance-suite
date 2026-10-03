import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";

export class OIDCCAddAcrValuesToAuthorizationEndpointRequest extends AbstractCondition {
	static readonly ACR_VALUES_SUPPORTED = "acr_values_supported";

	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request", "server"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		const acrValuesSupported = env.getElementFromObject(
			"server",
			OIDCCAddAcrValuesToAuthorizationEndpointRequest.ACR_VALUES_SUPPORTED,
		);
		const acrValues = env.getString("server", "acr_values");
		let acrValuesRequest: string;
		let msg: string;
		if (acrValuesSupported != null) {
			// include all values server supports
			const sj: string[] = [];

			for (const jsonElementAcrValue of acrValuesSupported as JsonArray) {
				sj.push(OIDFJSON.getString(jsonElementAcrValue));
			}
			acrValuesRequest = sj.join(" ");

			msg =
				"Added all acr values from server discovery document's " +
				OIDCCAddAcrValuesToAuthorizationEndpointRequest.ACR_VALUES_SUPPORTED +
				"to acr_values in authorization endpoint request.";
		} else if (acrValues) {
			// server doesn't support discovery; use user supplied value from test config
			acrValuesRequest = acrValues;
			msg = "Added acr_values from test configuration";
		} else {
			// include just '1' and '2' as per https://github.com/rohe/oidctest/blob/a306ff8ccd02da456192b595cf48ab5dcfd3d15a/src/oidctest/op/func.py#L365
			acrValuesRequest = "1 2";
			msg =
				"server discovery document does not contain " +
				OIDCCAddAcrValuesToAuthorizationEndpointRequest.ACR_VALUES_SUPPORTED +
				" (or, for static server config, test configuration does not contain acr_values) so setting acr_values in authorization endpoint request to '1 2'.";
		}

		authorizationEndpointRequest["acr_values"] = acrValuesRequest;

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess(msg, args("request", authorizationEndpointRequest, "acr_values", acrValuesRequest));

		return env;
	}
}

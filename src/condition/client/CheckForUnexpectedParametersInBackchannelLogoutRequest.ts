import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CheckForUnexpectedParametersInBackchannelLogoutRequest extends AbstractCondition {
	private static readonly EXPECTED_PARAMS: string[] = ["logout_token"];

	static override pre: EnvironmentRequirements = { required: ["backchannel_logout_request"] };

	override evaluate(env: Environment): Environment {
		const callbackParams = env.getElementFromObject("backchannel_logout_request", "body_form_params") as JsonObject;

		const unexpectedParams: JsonObject = {};

		for (const [key, value] of Object.entries(callbackParams)) {
			if (!CheckForUnexpectedParametersInBackchannelLogoutRequest.EXPECTED_PARAMS.includes(key)) {
				unexpectedParams[key] = value;
			}
		}

		if (Object.keys(unexpectedParams).length !== 0) {
			throw this.error(
				"backchannel_logout_request includes unexpected parameters. This may indicate the server has misunderstood the spec, or it may be using extensions the test suite is unaware of.",
				unexpectedParams,
			);
		}

		this.logSuccess("backchannel_logout_request includes only expected parameters", callbackParams);

		return env;
	}
}

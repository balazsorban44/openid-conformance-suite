import {
	AbstractCondition,
	has,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint extends AbstractCondition {
	private static readonly EXPECTED_PARAMS: string[] = [
		"error",
		"error_description",
		"error_uri",
		"state",
		"session_state",
		"iss", // https://tools.ietf.org/html/draft-ietf-oauth-iss-auth-resp
	];
	static readonly expectDummy1Dummy2Key = "expect_dummy1_dummy2";

	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const callbackParams = env.getObject("authorization_endpoint_response") as JsonObject;
		let expectedParams: string[];

		const expectDummy1Dummy2 = env.getBoolean(
			CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint.expectDummy1Dummy2Key,
		);
		if (expectDummy1Dummy2 != null && expectDummy1Dummy2 === true) {
			expectedParams = [...CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint.EXPECTED_PARAMS];
			expectedParams.push("dummy1");
			expectedParams.push("dummy2");
		} else {
			expectedParams = CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint.EXPECTED_PARAMS;
		}

		// https://openid.net/specs/openid-connect-core-1_0.html#AuthError
		if (has(callbackParams, "error")) {
			const unexpectedParams: JsonObject = {};

			for (const [key, value] of Object.entries(callbackParams)) {
				if (!expectedParams.includes(key)) {
					unexpectedParams[key] = value;
				}
			}

			if (Object.keys(unexpectedParams).length === 0) {
				this.logSuccess("error response includes only expected parameters", callbackParams);
			} else {
				throw this.error(
					"error response includes unexpected parameters. This may indicate the authorization server has misunderstood the spec, or it may be using extensions the test suite is unaware of.",
					unexpectedParams,
				);
			}
		} else {
			throw this.error("Authorization server was expected to return an error but did not", callbackParams);
		}
		return env;
	}
}

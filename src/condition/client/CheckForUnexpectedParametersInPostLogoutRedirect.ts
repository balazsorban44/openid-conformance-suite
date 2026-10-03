import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CheckForUnexpectedParametersInPostLogoutRedirect extends AbstractCondition {
	private static readonly EXPECTED_PARAMS: string[] = ["state"];

	static override pre: EnvironmentRequirements = { required: ["post_logout_redirect"] };

	override evaluate(env: Environment): Environment {
		const params = env.getElementFromObject("post_logout_redirect", "query_string_params") as JsonObject;

		const unexpectedParams: JsonObject = {};

		for (const [key, value] of Object.entries(params)) {
			if (!CheckForUnexpectedParametersInPostLogoutRedirect.EXPECTED_PARAMS.includes(key)) {
				unexpectedParams[key] = value;
			}
		}

		if (Object.keys(unexpectedParams).length !== 0) {
			throw this.error(
				"post_logout_redirect includes unexpected parameters in url query. This may indicate the server has misunderstood the spec, or it may be using extensions the test suite is unaware of.",
				unexpectedParams,
			);
		}

		this.logSuccess("post_logout_redirect includes only expected parameters", params);

		return env;
	}
}

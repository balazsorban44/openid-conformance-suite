import { AbstractCondition } from "../../framework/AbstractCondition.ts";
import { args } from "../../framework/DataUtils.ts";
import type { Environment } from "../../framework/Environment.ts";
import type { EnvironmentRequirements } from "../../framework/Condition.ts";

/**
 * Reports an incoming HTTP request to a path the test does not serve. Always fails when called;
 * the caller selects the severity - typically FAILURE, so a stray request (e.g. a wallet probing
 * sub-paths of the request_uri) fails the test, but without ending it: the request is answered
 * with a 404 and the test continues, so the real interaction can still complete and be checked.
 */
export class UnexpectedHttpRequestReceived extends AbstractCondition {
	static readonly ENV_KEY = "unexpected_http_request";

	static override pre: EnvironmentRequirements = { required: [UnexpectedHttpRequestReceived.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		const path = env.getString(UnexpectedHttpRequestReceived.ENV_KEY, "path");
		throw this.error(
			"Got an HTTP request to '" +
				path +
				"', a path the test does not serve; a 404 response was returned and the test continues",
			args("path", path, "method", env.getString(UnexpectedHttpRequestReceived.ENV_KEY, "method")),
		);
	}
}

import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

/**
 * this is explicitly checked when plain_http_request is selected
 */
export class EnsureRequestDoesNotContainRequestObject extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_http_request_params"] };

	override evaluate(env: Environment): Environment {
		const requestParam = env.getString("authorization_endpoint_http_request_params", "request");

		if (requestParam) {
			throw this.error("request parameter is not allowed", args("request", requestParam));
		} else {
			this.logSuccess("Request does not contain a request parameter");
			return env;
		}
	}
}

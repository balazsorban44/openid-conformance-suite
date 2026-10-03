import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

/**
 * OIDCC 6.1:
 * request and request_uri parameters MUST NOT be included in Request Objects.
 */
export class EnsureRequestObjectDoesNotContainRequestOrRequestUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_request_object"] };

	override evaluate(env: Environment): Environment {
		const requestClaim = env.getString("authorization_request_object", "claims.request");
		const requestUriClaim = env.getString("authorization_request_object", "claims.request_uri");

		if (requestClaim != null && requestUriClaim != null) {
			throw this.error(
				"request and request_uri parameters MUST NOT be included in Request Objects",
				args("request", requestClaim, "request_uri", requestUriClaim),
			);
		} else if (requestClaim != null) {
			throw this.error("request parameter MUST NOT be included in Request Objects", args("request", requestClaim));
		} else if (requestUriClaim != null) {
			throw this.error(
				"request_uri parameter MUST NOT be included in Request Objects",
				args("request_uri", requestUriClaim),
			);
		} else {
			this.logSuccess("Request object does not contain request or request_uri");
			return env;
		}
	}
}

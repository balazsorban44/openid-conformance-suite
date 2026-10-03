import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

/**
 * JAR 10.8:
 * never use the Client ID as the "sub" value in a Request Object.
 */
export class EnsureRequestObjectDoesNotContainSubWithClientId extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_request_object", "client"] };

	override evaluate(env: Environment): Environment {
		const sub = env.getString("authorization_request_object", "claims.sub");
		const clientId = env.getString("client", "client_id");

		if (sub && sub === clientId) {
			throw this.error(
				"Request object sub must not be Client ID - this is a security concern as it may allow the request object to be used as a client authentication assertion.",
				args("sub", clientId),
			);
		} else {
			this.logSuccess("Request object does not contain Client Id in sub");
			return env;
		}
	}
}

import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ValidateIssIfPresentInAuthorizationResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response", "server"] };

	override evaluate(env: Environment): Environment {
		const issuer = env.getString("server", "issuer");

		const authResponseIssuer = env.getString("authorization_endpoint_response", "iss");

		if (authResponseIssuer == null) {
			this.log("No 'iss' value in authorization response.");
			return env;
		}

		if (issuer !== authResponseIssuer) {
			throw this.error(
				"'iss' parameter in authorization response does not match server's issuer value.",
				args("expected", issuer, "actual", authResponseIssuer),
			);
		}

		this.logSuccess("'iss' parameter in authorization response matches server's issuer value.");

		return env;
	}
}

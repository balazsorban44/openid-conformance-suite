import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ValidateRequestObjectIss extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_request_object", "client"] };

	override evaluate(env: Environment): Environment {
		const clientId = env.getString("client", "client_id");
		const iss = env.getString("authorization_request_object", "claims.iss");

		if (iss == null) {
			throw this.error("Missing issuer, request object does not contain an 'iss' claim");
		}

		if (clientId !== iss) {
			throw this.error(
				"Issuer mismatch, iss claim does not match the client id",
				args("expected", clientId, "actual", iss),
			);
		}

		this.logSuccess("iss claim matches the client id", args("iss", iss));

		return env;
	}
}

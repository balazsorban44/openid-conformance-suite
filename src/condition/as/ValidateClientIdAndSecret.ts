import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ValidateClientIdAndSecret extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client_authentication", "client"] };

	override evaluate(env: Environment): Environment {
		const clientIdFromRequest = env.getString("client_authentication", "client_id");
		const clientSecretFromRequest = env.getString("client_authentication", "client_secret");

		const expectedClientId = env.getString("client", "client_id");
		const expectedClientSecret = env.getString("client", "client_secret");

		if (!clientIdFromRequest) {
			throw this.error(
				"Couldn't find client id in request",
				args("client_authentication", env.getObject("client_authentication")),
			);
		}

		if (expectedClientId === clientIdFromRequest && expectedClientSecret === clientSecretFromRequest) {
			this.logSuccess("Client id and secret match");
			return env;
		}

		throw this.error(
			"Client authentication failed",
			args(
				"expected_client_id",
				expectedClientId,
				"received_client_id",
				clientIdFromRequest,
				"expected_client_secret",
				expectedClientSecret,
				"received_client_secret",
				clientSecretFromRequest,
			),
		);
	}
}

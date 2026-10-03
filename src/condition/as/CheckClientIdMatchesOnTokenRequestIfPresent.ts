import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckClientIdMatchesOnTokenRequestIfPresent extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_request", "client"] };

	override evaluate(env: Environment): Environment {
		const clientId = env.getString("token_endpoint_request", "body_form_params.client_id");
		const expectedClientId = env.getString("client", "client_id");

		if (!clientId) {
			this.log("client_id not present, nothing to check");
			return env;
		}

		if (expectedClientId === clientId) {
			this.logSuccess("Extracted client_id matches the expected value", args("client_id", clientId));
			return env;
		}

		throw this.error(
			"client_id on the request " + clientId + " does not match the expected one " + expectedClientId,
			args("expected", expectedClientId, "actual", clientId),
		);
	}
}

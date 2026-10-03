import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

//TODO I could not see an equivalent check for FAPI
export class EnsureMTLSRequestContainsValidClientId extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_request", "client"] };

	override evaluate(env: Environment): Environment {
		const clientId = env.getString("token_endpoint_request", "body_form_params.client_id");

		if (!clientId) {
			throw this.error("Couldn't find client_id in form parameters");
		}
		const expectedClientId = env.getString("client", "client_id");
		if (expectedClientId !== clientId) {
			throw this.error(
				"client_id in request does not match the expected client_id",
				args("actual", clientId, "expected", expectedClientId),
			);
		}
		this.logSuccess("Request parameters contain a valid client_id parameter");
		return env;
	}
}

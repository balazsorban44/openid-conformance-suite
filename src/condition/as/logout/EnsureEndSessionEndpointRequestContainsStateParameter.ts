import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../../framework/index.ts";

export class EnsureEndSessionEndpointRequestContainsStateParameter extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["end_session_endpoint_http_request_params"] };

	override evaluate(env: Environment): Environment {
		const state = env.getString("end_session_endpoint_http_request_params", "state");

		if (state == null || state === "") {
			throw this.error("Missing state parameter. end_session_endpoint request must contain a state parameter");
		}

		this.logSuccess("end_session_endpoint request contains state parameter", args("state", state));

		return env;
	}
}

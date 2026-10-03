import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class RemoveIdTokenHintFromEndSessionEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["end_session_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["end_session_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const endSessionEndpointRequest = env.getObject("end_session_endpoint_request") as JsonObject;

		delete endSessionEndpointRequest["id_token_hint"];

		env.putObject("end_session_endpoint_request", endSessionEndpointRequest);

		this.logSuccess("Removed id_token_hint from end session endpoint request", endSessionEndpointRequest);

		return env;
	}
}

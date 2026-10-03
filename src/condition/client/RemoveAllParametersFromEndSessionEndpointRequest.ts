import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class RemoveAllParametersFromEndSessionEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["end_session_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["end_session_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const endSessionEndpointRequest: JsonObject = {};

		env.putObject("end_session_endpoint_request", endSessionEndpointRequest);

		this.logSuccess("Removed all parameters from end session endpoint request");

		return env;
	}
}

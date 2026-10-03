import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { CreateAuthorizationEndpointResponseParams } from "../CreateAuthorizationEndpointResponseParams.ts";

export class AddSessionStateToAuthorizationEndpointResponseParams extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: [CreateAuthorizationEndpointResponseParams.ENV_KEY, "session_state_data"],
	};
	static override post: EnvironmentRequirements = { required: [CreateAuthorizationEndpointResponseParams.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		const params = env.getObject(CreateAuthorizationEndpointResponseParams.ENV_KEY) as JsonObject;

		const sessionState = env.getString("session_state_data", "session_state");

		params["session_state"] = sessionState;

		env.putObject(CreateAuthorizationEndpointResponseParams.ENV_KEY, params);

		this.log(
			"Added session_state to authorization endpoint response params",
			args(CreateAuthorizationEndpointResponseParams.ENV_KEY, params),
		);

		return env;
	}
}

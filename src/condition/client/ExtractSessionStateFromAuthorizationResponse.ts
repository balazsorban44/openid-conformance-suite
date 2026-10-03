import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExtractSessionStateFromAuthorizationResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };
	static override post: EnvironmentRequirements = { strings: ["session_state"] };

	override evaluate(env: Environment): Environment {
		const sessionState = env.getString("authorization_endpoint_response", "session_state");
		if (!sessionState) {
			throw this.error("Couldn't find session_state in authorization_endpoint_response");
		}

		env.putString("session_state", sessionState);
		this.logSuccess("Found session_state", args("session_state", sessionState));
		return env;
	}
}

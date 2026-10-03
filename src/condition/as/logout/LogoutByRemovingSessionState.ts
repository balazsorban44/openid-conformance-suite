import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../../framework/index.ts";

export class LogoutByRemovingSessionState extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["session_state_data"] };
	static override post: EnvironmentRequirements = {};

	override evaluate(env: Environment): Environment {
		env.removeObject("session_state_data");

		this.log("Removed session state");

		return env;
	}
}

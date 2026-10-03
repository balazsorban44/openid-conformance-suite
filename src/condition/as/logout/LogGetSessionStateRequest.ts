import { AbstractCondition, args, type Environment } from "../../../framework/index.ts";

export class LogGetSessionStateRequest extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		const sessionStateData = env.getObject("session_state_data");
		if (sessionStateData != null) {
			this.log("OP iframe received postMessage request from RP iframe", args("returning_response", sessionStateData));
		} else {
			this.log("OP iframe received postMessage request from RP iframe but the user is not logged in");
		}
		return env;
	}
}

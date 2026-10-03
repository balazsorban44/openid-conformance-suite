import { AbstractCondition, type Environment } from "../../../framework/index.ts";

export class LogCheckSessionIframeRequest extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		this.log("The client requested check_session_iframe");
		return env;
	}
}

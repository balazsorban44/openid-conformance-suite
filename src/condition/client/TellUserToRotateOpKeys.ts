import { AbstractCondition, type Environment } from "../../framework/index.ts";

export class TellUserToRotateOpKeys extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		this.log("Please rotate the keys on the authorization server then press the 'Start' button.");

		return env;
	}
}

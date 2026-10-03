import { AbstractCondition, type Environment } from "../../framework/index.ts";

export class ClearAccessTokenFromRequest extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		env.removeNativeValue("incoming_access_token");

		this.log("Removed incoming access token from environment");

		return env;
	}
}

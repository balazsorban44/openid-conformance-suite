import { AbstractCondition, type Environment } from "../../framework/index.ts";

export class ServerAllowedReusingAuthorizationCode extends AbstractCondition {
	override evaluate(_env: Environment): Environment {
		throw this.error(
			"Server has incorrectly allowed a second use of an authorization code; an authorization code is expected to be single use.",
		);
	}
}

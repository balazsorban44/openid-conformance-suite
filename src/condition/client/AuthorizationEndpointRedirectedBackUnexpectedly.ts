import { AbstractCondition, type Environment } from "../../framework/index.ts";

export class AuthorizationEndpointRedirectedBackUnexpectedly extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		throw this.error("Authorization server redirected back in a case where it should not");
	}
}

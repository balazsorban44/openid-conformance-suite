import { AbstractCondition, type Environment } from "../../framework/index.ts";

export class EnsureOPDoesNotUseDefaultRedirectUriInCaseOfInvalidRedirectUri extends AbstractCondition {
	override evaluate(_env: Environment): Environment {
		throw this.error(
			"An invalid redirect_uri was included in the authorization request but the OP redirected to a " +
				"default redirect_uri instead of displaying an error page",
		);
	}
}

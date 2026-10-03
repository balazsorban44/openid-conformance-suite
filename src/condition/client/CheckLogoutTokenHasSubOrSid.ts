import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckLogoutTokenHasSubOrSid extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["logout_token"] };

	override evaluate(env: Environment): Environment {
		const sub = env.getElementFromObject("logout_token", "claims.sub");
		const sid = env.getElementFromObject("logout_token", "claims.sid");
		if (sub == null && sid == null) {
			throw this.error("logout token has neither sub nor sid - it must have at least one of them.");
		}

		this.logSuccess("logout token contains sub and/or sid");

		return env;
	}
}

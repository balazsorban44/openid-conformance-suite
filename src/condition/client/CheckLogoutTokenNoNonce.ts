import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckLogoutTokenNoNonce extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["logout_token"] };

	override evaluate(env: Environment): Environment {
		const nonce = env.getElementFromObject("logout_token", "claims.nonce");
		if (nonce != null) {
			throw this.error("Logout token has a nonce, which it must not.");
		}

		this.logSuccess("No nonce in logout token.");

		return env;
	}
}

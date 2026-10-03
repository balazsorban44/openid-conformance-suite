import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ValidateIdTokenNonce extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token"] };

	override evaluate(env: Environment): Environment {
		const incomingNonce = env.getString("id_token", "claims.nonce");

		const expectedNonce = env.getString("nonce");

		if (incomingNonce == null && expectedNonce == null) {
			this.logSuccess("nonce is not in id_token, as expected.");
			return env;
		}

		if (expectedNonce !== incomingNonce) {
			throw this.error("Nonce values mismatch", args("actual", incomingNonce, "expected", expectedNonce));
		} else {
			this.logSuccess("Nonce values match", args("nonce", incomingNonce));
		}

		return env;
	}
}

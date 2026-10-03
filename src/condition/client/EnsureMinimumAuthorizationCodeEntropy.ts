import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractEnsureMinimumEntropy } from "../AbstractEnsureMinimumEntropy.ts";

export class EnsureMinimumAuthorizationCodeEntropy extends AbstractEnsureMinimumEntropy {
	/**
	 * The actual amount of required entropy is 128 bits, but we can't accurately measure entropy so a bit of
	 * slop is allowed for.
	 */
	private readonly requiredEntropy = 96;

	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const authorizationCode = env.getString("authorization_endpoint_response", "code");
		if (!authorizationCode) {
			throw this.error("Can't find authorization code");
		}

		return this.ensureMinimumEntropy(env, authorizationCode, this.requiredEntropy);
	}
}

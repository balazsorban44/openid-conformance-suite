import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractEnsureMinimumEntropy } from "../AbstractEnsureMinimumEntropy.ts";

export class EnsureMinimumRefreshTokenEntropy extends AbstractEnsureMinimumEntropy {
	/**
	 * The actual amount of required entropy is 128 bits, but we can't accurately measure entropy so a bit of
	 * slop is allowed for.
	 */
	private readonly requiredEntropy = 96;

	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const refreshToken = env.getString("token_endpoint_response", "refresh_token");
		if (!refreshToken) {
			throw this.error("Can't find refresh token");
		}

		return this.ensureMinimumEntropy(env, refreshToken, this.requiredEntropy);
	}
}

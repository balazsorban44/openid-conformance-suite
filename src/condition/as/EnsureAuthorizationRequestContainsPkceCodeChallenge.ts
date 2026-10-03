import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { CreateEffectiveAuthorizationPARRequestParameters } from "./CreateEffectiveAuthorizationPARRequestParameters.ts";

export class EnsureAuthorizationRequestContainsPkceCodeChallenge extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: [CreateEffectiveAuthorizationPARRequestParameters.ENV_KEY],
	};
	static override post: EnvironmentRequirements = { strings: ["code_challenge", "code_challenge_method"] };

	override evaluate(env: Environment): Environment {
		const codeChallenge = env.getString(
			CreateEffectiveAuthorizationPARRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationPARRequestParameters.CODE_CHALLENGE,
		);
		const codeChallengeMethod = env.getString(
			CreateEffectiveAuthorizationPARRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationPARRequestParameters.CODE_CHALLENGE_METHOD,
		);

		if (!codeChallenge) {
			throw this.error("Missing required code_challenge parameter.");
		}
		if (!codeChallengeMethod) {
			throw this.error("Missing required code_challenge_method parameter.");
		}
		if ("S256" !== codeChallengeMethod) {
			throw this.error("S256 is required for PKCE.", args("code_challenge_method", codeChallengeMethod));
		}
		env.putString("code_challenge", codeChallenge);
		env.putString("code_challenge_method", codeChallengeMethod);

		this.logSuccess(
			"Found required PKCE parameters in request",
			args("code_challenge_method", codeChallengeMethod, "code_challenge", codeChallenge),
		);
		return env;
	}
}

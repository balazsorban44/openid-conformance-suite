import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class EnsureMaxAgeEqualsZeroAndPromptNone extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		const maxAge = env.getElementFromObject(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.MAX_AGE,
		);
		const maxAgeZero = 0;
		const prompt = env.getString(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.PROMPT,
		);

		if (maxAgeZero === maxAge && "none" === prompt) {
			this.logSuccess("The client sent max_age=0 and prompt=none as expected");
			return env;
		} else {
			throw this.error(
				"Invalid parameters. This test requires max_age=0 and prompt=none parameters",
				args("max_age", maxAge ?? null, "prompt", prompt),
			);
		}
	}
}

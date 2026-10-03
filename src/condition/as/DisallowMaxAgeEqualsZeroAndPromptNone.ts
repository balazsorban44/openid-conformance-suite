import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class DisallowMaxAgeEqualsZeroAndPromptNone extends AbstractCondition {
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
			throw this.error("Login required. Request contains max_age=0 and prompt=none parameters");
		} else {
			this.logSuccess("The client did not send max_age=0 and prompt=none parameters as expected");
			return env;
		}
	}
}

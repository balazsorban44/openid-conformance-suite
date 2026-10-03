import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class ExtractNonceFromAuthorizationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };
	static override post: EnvironmentRequirements = { strings: ["nonce"] };

	override evaluate(env: Environment): Environment {
		const nonce = env.getString(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.NONCE,
		);

		if (!nonce) {
			throw this.error("Couldn't find 'nonce' in authorization endpoint parameters");
		} else {
			env.putString("nonce", nonce);

			this.logSuccess("Extracted nonce", args("nonce", nonce));

			return env;
		}
	}
}

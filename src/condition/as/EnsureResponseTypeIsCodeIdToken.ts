import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractEnsureResponseType } from "./AbstractEnsureResponseType.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class EnsureResponseTypeIsCodeIdToken extends AbstractEnsureResponseType {
	static override pre: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		return this.ensureResponseTypeMatches(env, "code", "id_token");
	}
}

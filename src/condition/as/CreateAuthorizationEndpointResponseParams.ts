import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class CreateAuthorizationEndpointResponseParams extends AbstractCondition {
	static readonly ENV_KEY = "authorization_endpoint_response_params";
	static readonly REDIRECT_URI = "redirect_uri";
	static readonly STATE = "state";

	static override pre: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };
	static override post: EnvironmentRequirements = { required: [CreateAuthorizationEndpointResponseParams.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		const redirectUri = env.getString(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.REDIRECT_URI,
		);

		const state = env.getString(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.STATE,
		);

		const responseParams: JsonObject = {};
		if (redirectUri != null) {
			responseParams[CreateAuthorizationEndpointResponseParams.REDIRECT_URI] = redirectUri;
		}
		if (state != null) {
			responseParams[CreateAuthorizationEndpointResponseParams.STATE] = state;
		}

		this.logSuccess(
			"Added " + CreateAuthorizationEndpointResponseParams.ENV_KEY + " to environment",
			args("params", responseParams),
		);

		env.putObject(CreateAuthorizationEndpointResponseParams.ENV_KEY, responseParams);

		return env;
	}
}

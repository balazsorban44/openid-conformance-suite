import {
	AbstractCondition,
	args,
	has,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateAuthorizationEndpointResponseParams } from "./CreateAuthorizationEndpointResponseParams.ts";

export class CreateLoginRequiredErrorResponse extends AbstractCondition {
	static readonly ERROR_RESPONSE_PARAMS = "error_response_params";
	static readonly ERROR_RESPONSE_URL = "error_response_url";

	static override pre: EnvironmentRequirements = { required: [CreateAuthorizationEndpointResponseParams.ENV_KEY] };
	static override post: EnvironmentRequirements = {
		required: [CreateLoginRequiredErrorResponse.ERROR_RESPONSE_PARAMS],
		strings: [CreateLoginRequiredErrorResponse.ERROR_RESPONSE_URL],
	};

	override evaluate(env: Environment): Environment {
		const originalResponseParams = env.getObject(CreateAuthorizationEndpointResponseParams.ENV_KEY) as JsonObject;
		const errorResponseParams: JsonObject = {};
		if (has(originalResponseParams, "state")) {
			errorResponseParams["state"] = originalResponseParams["state"];
		}
		errorResponseParams["error"] = "login_required";
		errorResponseParams["error_description"] = "This is a login_required error response";
		env.putObject(CreateLoginRequiredErrorResponse.ERROR_RESPONSE_PARAMS, errorResponseParams);

		const removedRedirectUri = originalResponseParams["redirect_uri"];
		delete originalResponseParams["redirect_uri"];
		const responseUrl = OIDFJSON.getString(removedRedirectUri);
		env.putString(CreateLoginRequiredErrorResponse.ERROR_RESPONSE_URL, responseUrl);

		this.log(
			"Created login_required error",
			args(
				CreateLoginRequiredErrorResponse.ERROR_RESPONSE_PARAMS,
				errorResponseParams,
				CreateLoginRequiredErrorResponse.ERROR_RESPONSE_URL,
				responseUrl,
			),
		);

		return env;
	}
}

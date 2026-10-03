import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateAuthorizationEndpointResponseParams } from "./CreateAuthorizationEndpointResponseParams.ts";

import { toUriString } from "../../util/UriComponentsBuilder.ts";

export class SendAuthorizationResponseWithResponseModeQuery extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: [CreateAuthorizationEndpointResponseParams.ENV_KEY] };
	static override post: EnvironmentRequirements = { strings: ["authorization_endpoint_response_redirect"] };

	override evaluate(env: Environment): Environment {
		const params = env.getObject(CreateAuthorizationEndpointResponseParams.ENV_KEY) as JsonObject;

		const redirectUri = OIDFJSON.getString(params["redirect_uri"]);
		delete params["redirect_uri"];

		const queryParams: [string, string][] = [];
		for (const paramName of Object.keys(params)) {
			queryParams.push([paramName, OIDFJSON.getString(params[paramName])]);
		}

		const redirectTo = toUriString(redirectUri, queryParams);

		this.log("Redirecting back to client", args("uri", redirectTo));

		env.putString("authorization_endpoint_response_redirect", redirectTo);

		return env;
	}
}

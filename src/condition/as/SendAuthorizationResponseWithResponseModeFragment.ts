import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateAuthorizationEndpointResponseParams } from "./CreateAuthorizationEndpointResponseParams.ts";

import { encodeQueryParam } from "../../util/UriComponentsBuilder.ts";

export class SendAuthorizationResponseWithResponseModeFragment extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: [CreateAuthorizationEndpointResponseParams.ENV_KEY] };
	static override post: EnvironmentRequirements = { strings: ["authorization_endpoint_response_redirect"] };

	override evaluate(env: Environment): Environment {
		const params = env.getObject(CreateAuthorizationEndpointResponseParams.ENV_KEY) as JsonObject;

		const redirectUri = OIDFJSON.getString(params["redirect_uri"]);
		delete params["redirect_uri"];

		// UriComponentsBuilder.newInstance() with only query parameters; toUriString() gives "?name=value&name2=value2"
		const queryParams: string[] = [];
		for (const paramName of Object.keys(params)) {
			queryParams.push(encodeQueryParam(paramName) + "=" + encodeQueryParam(OIDFJSON.getString(params[paramName])));
		}
		let paramsAsString = queryParams.length > 0 ? "?" + queryParams.join("&") : "";

		if (paramsAsString.startsWith("?")) {
			paramsAsString = paramsAsString.substring(1);
		}

		const redirectTo = redirectUri + "#" + paramsAsString;

		this.log("Redirecting back to client", args("uri", redirectTo));

		env.putString("authorization_endpoint_response_redirect", redirectTo);

		return env;
	}
}

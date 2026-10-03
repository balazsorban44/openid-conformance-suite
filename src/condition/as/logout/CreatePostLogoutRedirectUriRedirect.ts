import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

import { toUriString } from "../../../util/UriComponentsBuilder.ts";

export class CreatePostLogoutRedirectUriRedirect extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["post_logout_redirect_uri_params", "end_session_endpoint_http_request_params"],
	};
	static override post: EnvironmentRequirements = { strings: ["post_logout_redirect_uri_redirect"] };

	override evaluate(env: Environment): Environment {
		const params = env.getObject("post_logout_redirect_uri_params") as JsonObject;
		const redirectUri = env.getString("end_session_endpoint_http_request_params", "post_logout_redirect_uri") as string;

		const queryParams: [string, string][] = [];
		for (const paramName of Object.keys(params)) {
			queryParams.push([paramName, OIDFJSON.getString(params[paramName])]);
		}

		const redirectTo = toUriString(redirectUri, queryParams);

		this.logSuccess("Created post_logout_redirect_uri redirect", args("uri", redirectTo));

		env.putString("post_logout_redirect_uri_redirect", redirectTo);

		return env;
	}
}

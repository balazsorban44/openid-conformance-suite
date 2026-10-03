import {
	AbstractCondition,
	args,
	isJsonPrimitive,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

import { toUriString } from "../../util/UriComponentsBuilder.ts";

export class BuildPlainRedirectToAuthorizationEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request", "server"] };
	static override post: EnvironmentRequirements = { strings: ["redirect_to_authorization_endpoint"] };

	override evaluate(env: Environment): Environment {
		if (!env.containsObject("authorization_endpoint_request")) {
			throw this.error("Couldn't find authorization endpoint request");
		}

		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		const authorizationEndpoint =
			env.getString("authorization_endpoint") != null
				? env.getString("authorization_endpoint")
				: env.getString("server", "authorization_endpoint");

		if (!authorizationEndpoint) {
			throw this.error("Couldn't find authorization endpoint");
		}

		// send a front channel request to start things off
		const queryParams: [string, string][] = [];

		for (const key of this.getParameterOrder(authorizationEndpointRequest)) {
			const element = authorizationEndpointRequest[key];

			// for nonce, state, client_id, redirect_uri, etc.
			if (isJsonPrimitive(element)) {
				if (key === "max_age") {
					queryParams.push([key, String(OIDFJSON.getNumber(element))]);
				} else {
					queryParams.push([key, OIDFJSON.getString(element)]);
				}
			}
			// for JSON objects/arrays (claims, dcql_query, client_metadata, etc.)
			else {
				queryParams.push([key, JSON.stringify(element)]);
			}
		}

		const redirectTo = toUriString(authorizationEndpoint, queryParams);

		this.logSuccess(
			"Sending to authorization endpoint",
			args("redirect_to_authorization_endpoint", redirectTo, "auth_request", authorizationEndpointRequest),
		);

		env.putString("redirect_to_authorization_endpoint", redirectTo);

		return env;
	}

	protected getParameterOrder(authorizationEndpointRequest: JsonObject): string[] {
		const keys = Object.keys(authorizationEndpointRequest);
		keys.sort();
		return keys;
	}
}

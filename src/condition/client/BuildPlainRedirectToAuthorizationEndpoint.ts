import {
	AbstractCondition,
	args,
	isJsonPrimitive,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Percent-encodes a query parameter name or value the way Spring's
 * UriComponentsBuilder.toUriString() does (HierarchicalUriComponents.Type.QUERY_PARAM):
 * unreserved characters, sub-delims other than '&' and '=', ':', '@', '/' and '?' are kept as they are,
 * everything else is percent-encoded as UTF-8.
 */
function encodeQueryParam(s: string): string {
	let out = "";
	for (const ch of s) {
		if (/^[A-Za-z0-9\-._~!$'()*+,;:@/?]$/.test(ch)) {
			out += ch;
		} else {
			for (const b of Buffer.from(ch, "utf8")) {
				out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
			}
		}
	}
	return out;
}

/** UriComponentsBuilder.fromUriString(uri).queryParam(...).toUriString() */
function appendQueryParams(uri: string, params: [string, string][]): string {
	let fragment = "";
	const hashIdx = uri.indexOf("#");
	if (hashIdx >= 0) {
		fragment = uri.substring(hashIdx);
		uri = uri.substring(0, hashIdx);
	}
	const query = params.map(([k, v]) => encodeQueryParam(k) + "=" + encodeQueryParam(v)).join("&");
	if (query === "") {
		return uri + fragment;
	}
	const sep = uri.includes("?") ? (uri.endsWith("?") || uri.endsWith("&") ? "" : "&") : "?";
	return uri + sep + query + fragment;
}

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

		const redirectTo = appendQueryParams(authorizationEndpoint, queryParams);

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

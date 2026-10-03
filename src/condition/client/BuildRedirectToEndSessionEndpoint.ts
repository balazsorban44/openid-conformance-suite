import {
	AbstractCondition,
	args,
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

export class BuildRedirectToEndSessionEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["end_session_endpoint_request", "server"] };
	static override post: EnvironmentRequirements = { strings: ["redirect_to_end_session_endpoint"] };

	override evaluate(env: Environment): Environment {
		const endSessionEndpointRequest = env.getObject("end_session_endpoint_request") as JsonObject;

		const endSessionEndpoint = env.getString("server", "end_session_endpoint");
		if (!endSessionEndpoint) {
			throw this.error("Couldn't find end_session endpoint");
		}

		// send a front channel request to start things off
		const queryParams: [string, string][] = [];

		for (const key of Object.keys(endSessionEndpointRequest)) {
			const element = endSessionEndpointRequest[key];
			queryParams.push([key, OIDFJSON.getString(element)]);
		}

		const redirectTo = appendQueryParams(endSessionEndpoint, queryParams);

		this.logSuccess("Sending to end_session endpoint", args("redirect_to_end_session_endpoint", redirectTo));

		env.putString("redirect_to_end_session_endpoint", redirectTo);

		return env;
	}
}

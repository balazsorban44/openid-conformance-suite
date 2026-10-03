import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

// Mirrors Spring's HierarchicalUriComponents.Type character classes (RFC 3986), used by
// UriComponentsBuilder.toUriString() which encodes the individual URI components.
const ALPHA_DIGIT = /[A-Za-z0-9]/;
function isUnreserved(c: string): boolean {
	return ALPHA_DIGIT.test(c) || c === "-" || c === "." || c === "_" || c === "~";
}
function isSubDelimiter(c: string): boolean {
	return "!$&'()*+,;=".includes(c);
}
function isPchar(c: string): boolean {
	return isUnreserved(c) || isSubDelimiter(c) || c === ":" || c === "@";
}

function encodeUriComponent(source: string, isAllowed: (c: string) => boolean): string {
	let out = "";
	for (const ch of source) {
		if (ch.length === 1 && isAllowed(ch)) {
			out += ch;
		} else {
			for (const b of Buffer.from(ch, "utf8")) {
				out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
			}
		}
	}
	return out;
}

// UriComponentsBuilder.URI_PATTERN
const URI_PATTERN =
	/^(?:([^:/?#]+):)?(?:\/\/(?:([^@[/?#]*)@)?(\[[0-9A-Fa-f:.]*[%A-Za-z0-9]*\]|[^[/?#:]*)(?::(\d*))?)?([^?#]*)(?:\?([^#]*))?(?:#(.*))?/;

const queryParamAllowed = (c: string) => c !== "=" && c !== "&" && (isPchar(c) || c === "/" || c === "?");

/** Equivalent of UriComponentsBuilder.fromUriString(uri).queryParam(...).toUriString() (components encoded) */
function buildAndEncode(uri: string, queryParams: [string, string][]): string {
	const m = URI_PATTERN.exec(uri);
	if (m == null) {
		throw new Error("[" + uri + "] is not a valid URI");
	}
	const [, scheme, userInfo, host, port, path, query, fragment] = m;
	const hasAuthority = uri.includes("//") && (host !== undefined || userInfo !== undefined || port !== undefined);

	const allQueryParams: [string, string | null][] = [];
	if (query !== undefined) {
		for (const pair of query.split("&")) {
			const eq = pair.indexOf("=");
			if (eq === -1) {
				allQueryParams.push([pair, null]);
			} else {
				allQueryParams.push([pair.substring(0, eq), pair.substring(eq + 1)]);
			}
		}
	}
	for (const [name, value] of queryParams) {
		allQueryParams.push([name, value]);
	}

	let result = "";
	if (scheme !== undefined) {
		result += scheme + ":";
	}
	if (hasAuthority) {
		result += "//";
		if (userInfo !== undefined) {
			result += encodeUriComponent(userInfo, (c) => isUnreserved(c) || isSubDelimiter(c) || c === ":") + "@";
		}
		if (host !== undefined) {
			result += host;
		}
		if (port !== undefined && port !== "") {
			result += ":" + port;
		}
	}
	if (path !== undefined) {
		result += encodeUriComponent(path, (c) => isPchar(c) || c === "/");
	}
	if (allQueryParams.length > 0) {
		result +=
			"?" +
			allQueryParams
				.map(([name, value]) => {
					const encodedName = encodeUriComponent(name, queryParamAllowed);
					return value === null ? encodedName : encodedName + "=" + encodeUriComponent(value, queryParamAllowed);
				})
				.join("&");
	}
	if (fragment !== undefined) {
		result += "#" + encodeUriComponent(fragment, (c) => isPchar(c) || c === "/" || c === "?");
	}
	return result;
}

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

		const redirectTo = buildAndEncode(redirectUri, queryParams);

		this.logSuccess("Created post_logout_redirect_uri redirect", args("uri", redirectTo));

		env.putString("post_logout_redirect_uri_redirect", redirectTo);

		return env;
	}
}

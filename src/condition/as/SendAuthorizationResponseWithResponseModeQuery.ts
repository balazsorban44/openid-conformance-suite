import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateAuthorizationEndpointResponseParams } from "./CreateAuthorizationEndpointResponseParams.ts";

// Port of the part of org.springframework.web.util.UriComponentsBuilder that is used here:
// fromUriString(uri).queryParam(name, value)...toUriString(). toUriString() percent-encodes (UTF-8) every URI
// component except for the characters that are allowed in that component, so e.g. a '%' in the original redirect
// uri is encoded again as %25 and a literal '+' in a parameter value is left alone.
const URI_PATTERN =
	/^(([^:/?#]+):)?(\/\/(([^@[/?#]*)@)?(\[[0-9a-fA-F:.]*[%A-Za-z0-9]*\]|[^[/?#:]*)(:(\d*(?:\{[^/]+?\})?))?)?([^?#]*)(\?([^#]*))?(#(.*))?$/s;
const QUERY_PARAM_PATTERN = /([^&=]+)(=?)([^&]+)?/g;

function isUnreserved(c: string): boolean {
	return /^[A-Za-z0-9\-._~]$/.test(c);
}

function isSubDelimiter(c: string): boolean {
	return "!$&'()*+,;=".includes(c);
}

function isPchar(c: string): boolean {
	return isUnreserved(c) || isSubDelimiter(c) || c === ":" || c === "@";
}

function encodeUriComponent(source: string, allowed: (c: string) => boolean): string {
	let out = "";
	for (const c of source) {
		if (c.length === 1 && c.charCodeAt(0) < 0x80 && allowed(c)) {
			out += c;
		} else {
			for (const b of Buffer.from(c, "utf8")) {
				out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
			}
		}
	}
	return out;
}

function toUriString(uri: string, queryParam: [string, string][]): string {
	const matcher = URI_PATTERN.exec(uri);
	if (matcher === null) {
		throw new Error("[" + uri + "] is not a valid URI");
	}
	const scheme = matcher[2];
	const userInfo = matcher[5];
	const host = matcher[6];
	const port = matcher[8];
	const path = matcher[9];
	const query = matcher[11];
	const fragment = matcher[13];

	let opaque = false;
	if (scheme) {
		const rest = uri.substring(scheme.length);
		if (!rest.startsWith(":/")) {
			opaque = true;
		}
	}

	if (opaque) {
		// an opaque uri has no query component, the added parameters are dropped
		let ssp = uri.substring(scheme.length + 1);
		if (fragment) {
			ssp = ssp.substring(0, ssp.length - (fragment.length + 1));
		}
		return scheme + ":" + ssp + (fragment && fragment.trim() ? "#" + fragment : "");
	}

	const queryParams: [string, string | null][] = [];
	if (query) {
		for (const m of query.matchAll(QUERY_PARAM_PATTERN)) {
			queryParams.push([m[1], m[3] !== undefined ? m[3] : m[2] ? "" : null]);
		}
	}
	for (const [name, value] of queryParam) {
		queryParams.push([name, value]);
	}

	let out = "";
	if (scheme) {
		out += scheme + ":";
	}
	if (userInfo != null || host != null) {
		out += "//";
		if (userInfo != null) {
			out += encodeUriComponent(userInfo, (c) => isUnreserved(c) || isSubDelimiter(c) || c === ":") + "@";
		}
		if (host != null) {
			out += host.startsWith("[") ? host : encodeUriComponent(host, (c) => isUnreserved(c) || isSubDelimiter(c));
		}
		if (port) {
			out += ":" + port;
		}
	}
	const encodedPath = encodeUriComponent(path ?? "", (c) => isPchar(c) || c === "/");
	if (encodedPath.length > 0) {
		if (out.length !== 0 && !encodedPath.startsWith("/")) {
			out += "/";
		}
		out += encodedPath;
	}
	if (queryParams.length > 0) {
		const isQueryParamChar = (c: string): boolean => c !== "=" && c !== "&" && (isPchar(c) || c === "/" || c === "?");
		out +=
			"?" +
			queryParams
				.map(([name, value]) => {
					const n = encodeUriComponent(name, isQueryParamChar);
					return value !== null ? n + "=" + encodeUriComponent(value, isQueryParamChar) : n;
				})
				.join("&");
	}
	if (fragment && fragment.trim()) {
		out += "#" + encodeUriComponent(fragment, (c) => isPchar(c) || c === "/" || c === "?");
	}
	return out;
}

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

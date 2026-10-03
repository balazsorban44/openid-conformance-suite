/**
 * URIs as upstream handles them: `java.net.URI` parsing (where upstream calls `new URI(String)` and the WHATWG `URL`
 * parser would accept or reject different inputs), Spring's UriComponentsBuilder (adding query parameters to a
 * URI), and the redirect_uri rules of upstream's util/validation/RedirectURIValidationUtil.
 */
import { isIPv6 } from "node:net";
import { NamedError } from "./errors.ts";

/** Port of `java.net.URISyntaxException`. */
export class URISyntaxException extends NamedError {}

/** The components of a `java.net.URI` that the ported conditions use. */
export interface JavaURI {
	/** java.net.URI.getScheme() */
	scheme: string | null;
	/** java.net.URI.getHost() (null for registry-based or missing authorities) */
	host: string | null;
	/** java.net.URI.getPort() (-1 when undefined) */
	port: number;
	/** java.net.URI.getRawFragment() (null when there is no '#') */
	fragment: string | null;
}

const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const DIGIT = "0123456789";
const ALPHANUM = ALPHA + DIGIT;
const MARK = "-_.!~*'()";
const UNRESERVED = ALPHANUM + MARK;
const RESERVED = ";/?:@&=+$,[]";
const URIC = RESERVED + UNRESERVED;
const PCHAR = UNRESERVED + ":@&=+$,";
const PATH = PCHAR + ";/";
const USERINFO = UNRESERVED + ";:&=+$,";
const REG_NAME = UNRESERVED + "$,;:@&=+";
const SERVER = USERINFO + ALPHANUM + "-.:@[]";
const SCHEME = ALPHA + DIGIT + "+-.";

/**
 * Port of the parts of `new java.net.URI(String)` (java.net.URI.Parser, RFC 2396 + RFC 2732) that the ported
 * conditions rely on: the same accept/reject decisions and URISyntaxException messages, and getScheme(), getHost()
 * getPort() and getFragment() (WHATWG `URL` differs: it accepts/normalizes many inputs java.net.URI rejects, lowercases the
 * host and cannot tell an empty fragment from a missing one).
 *
 * @throws URISyntaxException
 */
export function parseJavaURI(input: string): JavaURI {
	const n = input.length;
	const result: JavaURI = { scheme: null, host: null, port: -1, fragment: null };

	const fail = (reason: string, p: number): never => {
		throw new URISyntaxException(reason + " at index " + p + ": " + input);
	};
	const at = (p: number, c: string): boolean => p < n && input.charAt(p) === c;
	// java.net.URI.Parser.scanEscape: escaped octets and (where escapes are allowed) non-ASCII "other" chars
	const scanEscape = (p: number): number => {
		const c = input.charAt(p);
		if (c === "%") {
			if (p + 3 <= n && /^[0-9A-Fa-f]{2}$/.test(input.substring(p + 1, p + 3))) {
				return p + 3;
			}
			fail("Malformed escape pair", p);
		} else if (c.charCodeAt(0) > 128 && !/^[\s\p{Zs}\p{Zl}\p{Zp}\p{Cc}]$/u.test(c)) {
			return p + 1;
		}
		return p;
	};
	// scan(start, end, lowMask, highMask)
	const scanChars = (start: number, end: number, allowed: string, escapes: boolean): number => {
		let p = start;
		while (p < end) {
			const c = input.charAt(p);
			if (allowed.includes(c)) {
				p++;
				continue;
			}
			if (escapes) {
				const q = scanEscape(p);
				if (q > p) {
					p = q;
					continue;
				}
			}
			break;
		}
		return p;
	};
	// scan(start, end, err, stop)
	const scanStop = (start: number, end: number, err: string, stop: string): number => {
		let p = start;
		while (p < end) {
			const c = input.charAt(p);
			if (err.includes(c)) {
				return -1;
			}
			if (stop.includes(c)) {
				break;
			}
			p++;
		}
		return p;
	};
	const checkChars = (start: number, end: number, allowed: string, escapes: boolean, what: string): void => {
		const p = scanChars(start, end, allowed, escapes);
		if (p < end) {
			fail("Illegal character in " + what, p);
		}
	};

	const parseHostname = (start: number, end: number): number => {
		let p = start;
		let l = -1;
		do {
			let q = scanChars(p, end, ALPHANUM, false);
			if (q <= p) {
				break;
			}
			l = p;
			p = q;
			q = scanChars(p, end, ALPHANUM + "-", false);
			if (q > p) {
				if (input.charAt(q - 1) === "-") {
					fail("Illegal character in hostname", q - 1);
				}
				p = q;
			}
			q = scanChars(p, end, ".", false);
			if (q <= p) {
				break;
			}
			p = q;
		} while (p < end);
		if (p < end && !at(p, ":")) {
			fail("Illegal character in hostname", p);
		}
		if (l < 0) {
			fail("Expected hostname", start);
		}
		// for a fully qualified hostname check that the rightmost label starts with an alpha character.
		if (l > start && !ALPHA.includes(input.charAt(l))) {
			fail("Illegal character in hostname", l);
		}
		result.host = input.substring(start, p);
		return p;
	};

	const parseIPv4Address = (start: number, end: number): number => {
		const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/.exec(input.substring(start, end));
		if (m == null || m.slice(1).some((o) => Number(o) > 255)) {
			return -1;
		}
		const p = start + m[0].length;
		if (p < end && !at(p, ":")) {
			// not followed by a port: not an IPv4 address after all, try a hostname
			return -1;
		}
		result.host = input.substring(start, p);
		return p;
	};

	const parseServer = (start: number, end: number): number => {
		let p = start;
		let q = scanStop(p, end, "/?#", "@");
		if (q >= p && q < end && input.charAt(q) === "@") {
			checkChars(p, q, USERINFO, true, "user info");
			p = q + 1;
		}
		if (at(p, "[")) {
			p++;
			q = scanStop(p, end, "/?#", "]");
			if (q > p && q < end && input.charAt(q) === "]") {
				const r = scanStop(p, q, "", "%");
				if (!isIPv6(input.substring(p, r))) {
					fail("Malformed IPv6 address", p);
				}
				result.host = input.substring(p - 1, q + 1);
				p = q + 1;
			} else {
				fail("Expected closing bracket for IPv6 address", q);
			}
		} else {
			q = parseIPv4Address(p, end);
			if (q <= p) {
				q = parseHostname(p, end);
			}
			p = q;
		}
		if (at(p, ":")) {
			p++;
			q = scanChars(p, end, DIGIT, false);
			if (q > p) {
				result.port = Number.parseInt(input.substring(p, q), 10);
				if (result.port > 2147483647) {
					fail("Malformed port number", p);
				}
			}
			p = q;
		}
		if (p < end) {
			fail("Illegal character in port number", p);
		}
		return p;
	};

	const parseAuthority = (start: number, end: number): number => {
		const serverChars = scanChars(start, end, SERVER, true) === end;
		const regChars = scanChars(start, end, REG_NAME, true) === end;
		if (regChars && !serverChars) {
			return end;
		}
		let q = start;
		let ex: unknown = null;
		if (serverChars) {
			try {
				q = parseServer(start, end);
				if (q < end) {
					fail("Expected end of authority", q);
				}
			} catch (x) {
				if (!(x instanceof URISyntaxException)) {
					throw x;
				}
				result.host = null;
				result.port = -1;
				ex = x;
				q = start;
			}
		}
		if (q < end) {
			if (regChars) {
				// registry-based authority
			} else if (ex != null) {
				throw ex;
			} else {
				fail("Illegal character in authority", q);
			}
		}
		return end;
	};

	const parseHierarchical = (start: number): number => {
		let p = start;
		if (at(p, "/") && at(p + 1, "/")) {
			p += 2;
			const q = scanStop(p, n, "", "/?#");
			if (q > p) {
				p = parseAuthority(p, q);
			} else if (q < n) {
				// DEVIATION: Allow empty authority prior to non-empty path, query component or fragment identifier
			} else {
				fail("Expected authority", p);
			}
		}
		let q = scanStop(p, n, "", "?#");
		checkChars(p, q, PATH, true, "path");
		p = q;
		if (at(p, "?")) {
			p++;
			q = scanStop(p, n, "", "#");
			checkChars(p, q, URIC, true, "query");
			p = q;
		}
		return p;
	};

	let p = scanStop(0, n, "/?#", ":");
	if (p >= 0 && at(p, ":")) {
		if (p === 0) {
			fail("Expected scheme name", 0);
		}
		if (!ALPHA.includes(input.charAt(0))) {
			fail("Illegal character in scheme name", 0);
		}
		checkChars(1, p, SCHEME, false, "scheme name");
		result.scheme = input.substring(0, p);
		p++; // Skip ':'
		if (at(p, "/")) {
			p = parseHierarchical(p);
		} else {
			// opaque; need to create the schemeSpecificPart
			const q = scanStop(p, n, "", "#");
			if (q <= p) {
				fail("Expected scheme-specific part", p);
			}
			checkChars(p, q, URIC, true, "opaque part");
			p = q;
		}
	} else {
		p = parseHierarchical(0);
	}
	if (at(p, "#")) {
		checkChars(p + 1, n, URIC, true, "fragment");
		result.fragment = input.substring(p + 1, n);
		p = n;
	}
	if (p < n) {
		fail("end of URI", p);
	}
	return result;
}

/**
 * The parts of org.springframework.web.util.UriComponentsBuilder / HierarchicalUriComponents that the ported
 * conditions use: `fromUriString(uri).queryParam(name, value)...toUriString()`.
 *
 * `toUriString()` percent-encodes (UTF-8) every URI component except for the characters that are allowed in that
 * component (RFC 3986 character classes), so e.g. a '%' in the original uri is encoded again as %25 and a space
 * in a query parameter value becomes %20.
 *
 * UPSTREAM DEVIATION: Spring treats '+' as an allowed sub-delimiter in query parameters and leaves it as is,
 * but every form-decoding server (Spring/Tomcat, Apache httpclient's URLEncodedUtils, Node's URLSearchParams)
 * turns a literal '+' back into a space. A client_id generated by the suite's own RP tests
 * (RFC6749AppendixASyntaxUtils) can contain '+', which breaks suite-vs-suite runs, so '+' is encoded as %2B
 * here. A conformant server decodes %2B to '+', so the decoded parameter values are the same as upstream's.
 *
 * Spring's HierarchicalUriComponents.Type: RFC 3986 unreserved
 */
export function isUnreserved(c: string): boolean {
	return /^[A-Za-z0-9\-._~]$/.test(c);
}

export function isSubDelimiter(c: string): boolean {
	return "!$&'()*+,;=".includes(c);
}

export function isPchar(c: string): boolean {
	return isUnreserved(c) || isSubDelimiter(c) || c === ":" || c === "@";
}

/** HierarchicalUriComponents.Type.QUERY_PARAM.isAllowed, minus '+' (see the note above) */
export function isQueryParamChar(c: string): boolean {
	return c !== "=" && c !== "&" && c !== "+" && (isPchar(c) || c === "/" || c === "?");
}

export function encodeUriComponent(source: string, allowed: (c: string) => boolean): string {
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

/** Percent-encodes a query parameter name or value (HierarchicalUriComponents.Type.QUERY_PARAM) */
export function encodeQueryParam(s: string): string {
	return encodeUriComponent(s, isQueryParamChar);
}

// UriComponentsBuilder.URI_PATTERN
const URI_PATTERN =
	/^(([^:/?#]+):)?(\/\/(([^@[/?#]*)@)?(\[[0-9a-fA-F:.]*[%A-Za-z0-9]*\]|[^[/?#:]*)(:(\d*(?:\{[^/]+?\})?))?)?([^?#]*)(\?([^#]*))?(#(.*))?$/s;
const QUERY_PARAM_PATTERN = /([^&=]+)(=?)([^&]+)?/g;

/**
 * UriComponentsBuilder.fromUriString(uri).queryParam(name, value)...toUriString(): the given parameters are
 * appended to the uri's existing query and every component is encoded.
 */
export function toUriString(uri: string, queryParam: [string, string | null][]): string {
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
		out +=
			"?" +
			queryParams
				.map(([name, value]) => {
					const n = encodeQueryParam(name);
					return value !== null ? n + "=" + encodeQueryParam(value) : n;
				})
				.join("&");
	}
	if (fragment && fragment.trim()) {
		out += "#" + encodeUriComponent(fragment, (c) => isPchar(c) || c === "/" || c === "?");
	}
	return out;
}

/**
 * The redirect_uri of a web client (or a client without application_type) may be http only for the code flow
 * (false if invalid).
 *
 * upstream: util/validation/RedirectURIValidationUtil.java
 */
export function requireHttpsIfWebAndResponseTypeNotCode(
	applicationType: string | null | undefined,
	responseType: string | null | undefined,
	redirectUri: string,
): boolean {
	if ("web" === applicationType || applicationType == null) {
		if (redirectUri.toLowerCase().startsWith("http://")) {
			if ("code" === responseType) {
				return true;
			} else {
				return false;
			}
		}
	}
	return true;
}

/** upstream: util/validation/RedirectURIValidationUtil.java */
export function isLocalhost(hostname: string): boolean {
	if (hostname === "localhost") {
		return true;
	}
	if (hostname === "127.0.0.1") {
		return true;
	}
	if (hostname === "::1" || hostname === "[::1]") {
		return true;
	}
	return false;
}

/**
 *
 * @param applicationType
 * @param redirectUri
 * @return false if invalid
 * @throws URISyntaxException
 *
 * upstream: util/validation/RedirectURIValidationUtil.java
 */
export function dontAllowHttpIfNativeAndNotLocalhost(
	applicationType: string | null | undefined,
	redirectUri: string,
): boolean {
	if ("native" === applicationType) {
		const actualLower = redirectUri.toLowerCase();
		if (actualLower.startsWith("http://")) {
			const host = uriHost(redirectUri);
			if (!isLocalhost(host)) {
				return false;
			}
		}
	}
	return true;
}

/**
 * `new URI(redirectUri).getHost()` for an http URI: the host exactly as written (java.net.URI does not
 * lowercase it, unlike WHATWG URL), IPv6 literals keep their brackets.
 */
function uriHost(redirectUri: string): string {
	if (!URL.canParse(redirectUri) || /[\s"<>\\^`{|}]/.test(redirectUri)) {
		throw new URISyntaxException("Illegal character or malformed URI: " + redirectUri);
	}
	const m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)/.exec(redirectUri);
	const host = m?.[1] ?? "";
	if (host.length === 0) {
		// java.net.URI.getHost() returns null here, which makes isLocalhost throw a NullPointerException
		throw new TypeError('Cannot invoke "String.equals(Object)" because "hostname" is null');
	}
	return host;
}

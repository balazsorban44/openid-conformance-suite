/**
 * Validates an RFC 8414 §2 issuer-identifier URL: it must be a syntactically valid URI using the
 * {@code https} scheme (case-insensitive per RFC 3986 §3.1), have a host component, and carry no
 * fragment, query, userinfo or out-of-range port.
 *
 * UPSTREAM: Java uses java.net.URI, whose parser has no equivalent in JavaScript (WHATWG URL normalises and
 * rejects different things). The RFC 3986 appendix B decomposition plus java.net.URI's character and server-based
 * authority rules are reimplemented below; the wording of the "is not a valid URI" detail differs from Java's
 * URISyntaxException message.
 */
export class IssuerUrlValidation {
	// RFC 3986 appendix B
	private static readonly URI_PATTERN = /^(?:([^:/?#]+):)?(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/s;

	private static readonly HOSTNAME_PATTERN =
		/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.?$/;
	private static readonly IPV4_PATTERN = /^\d{1,3}(?:\.\d{1,3}){3}$/;
	private static readonly IPV6_PATTERN = /^\[[0-9A-Fa-f:.]+\]$/;

	/**
	 * Appends one issue per problem found with {@code value} to {@code issues}.
	 *
	 * @param value  the URL to validate
	 * @param label  the field label used to prefix each issue message, e.g. {@code "credential_issuer"}
	 *               or {@code "authorization_servers[0]"}
	 * @param issues collector for human-readable problem descriptions
	 */
	static validate(value: string, label: string, issues: string[]): void {
		const syntaxError = IssuerUrlValidation.uriSyntaxError(value);
		if (syntaxError != null) {
			issues.push(`${label}: '${value}' is not a valid URI (${syntaxError})`);
			return;
		}
		const m = IssuerUrlValidation.URI_PATTERN.exec(value) as RegExpExecArray;
		const scheme = m[1];
		const authority = m[2];
		const query = m[4];
		const fragment = m[5];
		const { host, userInfo, port } = IssuerUrlValidation.parseAuthority(authority);

		if (scheme == null || scheme.toLowerCase() !== "https") {
			issues.push(`${label}: '${value}' must use the https scheme`);
		}
		if (host == null || host === "") {
			issues.push(`${label}: '${value}' is missing a host component`);
		}
		if (fragment != null) {
			issues.push(`${label}: '${value}' must not contain a fragment part`);
		}
		if (query != null) {
			issues.push(`${label}: '${value}' must not contain a query part`);
		}
		if (userInfo != null) {
			issues.push(`${label}: '${value}' must not contain userinfo`);
		}
		// URI.getPort() returns -1 when absent or a non-negative int otherwise, so only the upper
		// bound can be violated.
		if (port > 65535) {
			issues.push(`${label}: '${value}' contains an out-of-range port (${port})`);
		}
	}

	/** Approximation of the checks java.net.URI's parser performs; null if the string is a valid URI */
	private static uriSyntaxError(value: string): string | null {
		for (let i = 0; i < value.length; i++) {
			const c = value.charCodeAt(i);
			const ch = value.charAt(i);
			if (c <= 0x20 || c === 0x7f || '"<>\\^`{|}'.includes(ch)) {
				return `Illegal character at index ${i}: ${value}`;
			}
			if (ch === "%" && !/^[0-9A-Fa-f]{2}$/.test(value.substring(i + 1, i + 3))) {
				return `Malformed escape pair at index ${i}: ${value}`;
			}
		}
		const m = IssuerUrlValidation.URI_PATTERN.exec(value);
		if (m == null) {
			return `Illegal character in URI: ${value}`;
		}
		if (m[1] != null && !/^[A-Za-z][A-Za-z0-9+.-]*$/.test(m[1])) {
			return `Illegal character in scheme name at index 0: ${value}`;
		}
		// square brackets are only permitted around an IPv6 literal in the authority
		const rest = (m[3] ?? "") + (m[4] ?? "") + (m[5] ?? "");
		if (/[[\]]/.test(rest)) {
			return `Illegal character in URI: ${value}`;
		}
		return null;
	}

	/** Server-based authority parsing as in java.net.URI; falls back to "no host" (registry-based authority) */
	private static parseAuthority(authority: string | undefined): {
		host: string | null;
		userInfo: string | null;
		port: number;
	} {
		const none = { host: null, userInfo: null, port: -1 };
		if (authority == null || authority === "") {
			return none;
		}
		let rest = authority;
		let userInfo: string | null = null;
		const at = rest.lastIndexOf("@");
		if (at >= 0) {
			userInfo = rest.substring(0, at);
			rest = rest.substring(at + 1);
		}
		let hostPart = rest;
		let portPart: string | null = null;
		if (rest.startsWith("[")) {
			const close = rest.indexOf("]");
			if (close < 0) {
				return none;
			}
			hostPart = rest.substring(0, close + 1);
			const after = rest.substring(close + 1);
			if (after !== "") {
				if (!after.startsWith(":")) {
					return none;
				}
				portPart = after.substring(1);
			}
		} else {
			const colon = rest.lastIndexOf(":");
			if (colon >= 0) {
				hostPart = rest.substring(0, colon);
				portPart = rest.substring(colon + 1);
			}
		}
		const validHost =
			IssuerUrlValidation.HOSTNAME_PATTERN.test(hostPart) ||
			IssuerUrlValidation.IPV4_PATTERN.test(hostPart) ||
			IssuerUrlValidation.IPV6_PATTERN.test(hostPart);
		if (!validHost) {
			return none;
		}
		let port = -1;
		if (portPart != null && portPart !== "") {
			if (!/^\d+$/.test(portPart) || Number(portPart) > 2147483647) {
				return none;
			}
			port = Number(portPart);
		}
		return { host: hostPart, userInfo, port };
	}
}

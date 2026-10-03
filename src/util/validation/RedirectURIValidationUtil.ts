/** Port of `java.net.URISyntaxException` as thrown by {@link RedirectURIValidationUtil}. */
export class URISyntaxException extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "URISyntaxException";
	}
}

export class RedirectURIValidationUtil {
	/**
	 *
	 * @param applicationType
	 * @param responseType
	 * @param redirectUri
	 * @return false if invalid
	 */
	static requireHttpsIfWebAndResponseTypeNotCode(
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

	static isLocalhost(hostname: string): boolean {
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
	 */
	static dontAllowHttpIfNativeAndNotLocalhost(applicationType: string | null | undefined, redirectUri: string): boolean {
		if ("native" === applicationType) {
			const actualLower = redirectUri.toLowerCase();
			if (actualLower.startsWith("http://")) {
				const host = RedirectURIValidationUtil.uriHost(redirectUri);
				if (!RedirectURIValidationUtil.isLocalhost(host)) {
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
	private static uriHost(redirectUri: string): string {
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
}

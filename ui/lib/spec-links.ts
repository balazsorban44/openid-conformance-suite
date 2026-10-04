/**
 * Links for the requirement tags of log entries ("OIDCC-3.1.3.7" -> the section of OpenID Connect Core), as
 * upstream's log view links them: the prefixes of the specifications this suite's plans cite, from upstream
 * export/LogEntryHelper.java (specLinks); the longest matching prefix wins.
 */
const SPEC_LINKS: Record<string, string> = {
	"OIDCC-": "https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.",
	"OIDCR-": "https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.",
	"OIDCD-": "https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.",
	"OIDCBCL-": "https://openid.net/specs/openid-connect-backchannel-1_0.html#rfc.section.",
	"OIDCFCL-": "https://openid.net/specs/openid-connect-frontchannel-1_0.html#rfc.section.",
	"OIDCSM-": "https://openid.net/specs/openid-connect-session-1_0.html#rfc.section.",
	"OIDCRIL-": "https://openid.net/specs/openid-connect-rpinitiated-1_0.html#rfc.section.",
	"OAuth2-FP-": "https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#rfc.section.",
	"OAuth2-RT-": "https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#rfc.section.",
	"OAuth2-iss-": "https://tools.ietf.org/html/rfc9207#section-",
	"RFC3986-": "https://tools.ietf.org/html/rfc3986#section-",
	"RFC6749-": "https://tools.ietf.org/html/rfc6749#section-",
	"RFC6749A-": "https://tools.ietf.org/html/rfc6749#appendix-",
	"RFC6750-": "https://tools.ietf.org/html/rfc6750#section-",
	"RFC6819-": "https://tools.ietf.org/html/rfc6819#section-",
	"RFC7231-": "https://tools.ietf.org/html/rfc7231#section-",
	"RFC7517-": "https://tools.ietf.org/html/rfc7517#section-",
	"RFC7518-": "https://tools.ietf.org/html/rfc7518#section-",
	"RFC7519-": "https://tools.ietf.org/html/rfc7519#section-",
	"RFC7521-": "https://tools.ietf.org/html/rfc7521#section-",
	"RFC7523-": "https://tools.ietf.org/html/rfc7523#section-",
	"RFC7591-": "https://tools.ietf.org/html/rfc7591#section-",
	"RFC7592-": "https://tools.ietf.org/html/rfc7592#section-",
	"RFC7636-": "https://tools.ietf.org/html/rfc7636#section-",
	"RFC7662-": "https://tools.ietf.org/html/rfc7662#section-",
	"RFC8414-": "https://tools.ietf.org/html/rfc8414#section-",
	"RFC8417-": "https://tools.ietf.org/html/rfc8417#section-",
	"RFC8485-": "https://tools.ietf.org/html/rfc8485#section-",
	"RFC8705-": "https://tools.ietf.org/html/rfc8705#section-",
	"RFC8707-": "https://tools.ietf.org/html/rfc8707#section-",
	"RFC9396-": "https://tools.ietf.org/html/rfc9396#section-",
	"BCP195-": "https://tools.ietf.org/html/bcp195#section-",
	"PAR-": "https://www.rfc-editor.org/rfc/rfc9126.html#section-",
	"JAR-": "https://www.rfc-editor.org/rfc/rfc9101.html#section-",
	"DPOP-": "https://www.rfc-editor.org/rfc/rfc9449#section-",
	"JARM-": "https://openid.net/specs/oauth-v2-jarm.html#section-",
};

export function specLink(requirement: string): string | null {
	let best = "";
	for (const prefix of Object.keys(SPEC_LINKS)) {
		if (requirement.startsWith(prefix) && prefix.length > best.length) {
			best = prefix;
		}
	}
	return best ? SPEC_LINKS[best] + requirement.slice(best.length) : null;
}

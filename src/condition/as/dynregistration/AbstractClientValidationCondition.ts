import { isIPv6 } from "node:net";
import { AbstractCondition, isJsonArray, OIDFJSON, type JsonArray, type JsonObject } from "../../../framework/index.ts";
import { URISyntaxException } from "../../../util/validation/RedirectURIValidationUtil.ts";

/**
 * Port of `java.lang.IllegalStateException` as thrown by Gson's `JsonElement.getAsJsonArray()` on a non-array
 * element. Subclasses catch it (`catch (IllegalStateException ex)` upstream).
 */
export class IllegalStateException extends Error {
	constructor(message: string) {
		super(message);
		this.name = "IllegalStateException";
	}
}

/** Gson JsonElement.getAsJsonArray(): throws IllegalStateException if the element is not an array */
export function getAsJsonArray(el: unknown): JsonArray {
	if (!isJsonArray(el)) {
		throw new IllegalStateException("Not a JSON Array: " + JSON.stringify(el));
	}
	return el;
}

/** The components of a `java.net.URI` that the conditions in this package use. */
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
 * Port of the parts of `new java.net.URI(String)` (java.net.URI.Parser, RFC 2396 + RFC 2732) that the conditions in
 * this package rely on: the same accept/reject decisions and URISyntaxException messages, and getScheme(), getHost()
 * getPort() and getFragment() (WHATWG `URL` differs: it accepts/normalizes many inputs java.net.URI rejects, lowercases the
 * host and cannot tell an empty fragment from a missing one).
 *
 * Private helper (not in src/util yet).
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
 * As per https://gitlab.com/openid/conformance-suite/-/merge_requests/865#note_294594618
 * having a Condition class with accessor/utility methods which are intended to be used
 * by Condition classes extending from that class is not considered as a good pattern and
 * should not be used.
 * The recommended approach is to place methods in individual condition classes without using
 * a common base class with utility methods.
 * This is not a good pattern and shouldn't be followed elsewhere.
 */
export abstract class AbstractClientValidationCondition extends AbstractCondition {
	/**
	 * don't forget to set in evaluate methods
	 */
	protected client!: JsonObject;
	protected validationErrors: Record<string, unknown>[] = [];

	protected appendError(keyForMessage: string, msg: string, keyForArgs: string, args: Record<string, unknown>): void {
		this.validationErrors.push({ [keyForMessage]: msg, [keyForArgs]: args });
	}

	/**
	 * REQUIRED. Array of Redirection URI values used by the Client. One of these registered Redirection
	 * URI values MUST exactly match the redirect_uri parameter value used in each Authorization Request,
	 * with the matching performed as described in Section 6.2.1 of [RFC3986] (Simple String Comparison).
	 * @return
	 */
	protected getRedirectUris(): JsonArray | null {
		if ("redirect_uris" in this.client) {
			return getAsJsonArray(this.client["redirect_uris"]);
		}
		return null;
	}

	/**
	 * OPTIONAL. JSON array containing a list of the OAuth 2.0 response_type values that the Client is
	 * declaring that it will restrict itself to using. If omitted, the default is that the Client will
	 * use only the code Response Type.
	 * @return
	 */
	protected getResponseTypes(): JsonArray {
		if ("response_types" in this.client) {
			return getAsJsonArray(this.client["response_types"]);
		}
		const defaultValue: JsonArray = [];
		defaultValue.push("code");
		return defaultValue;
	}

	/**
	 * checks if response type contains only code or not
	 * return true if it's not only code or null
	 * @return
	 */
	protected hasImplicitResponseTypes(): boolean {
		const responseTypes = this.getResponseTypes();
		if (responseTypes == null) {
			return false;
		}
		if (responseTypes.length === 1 && "code" === OIDFJSON.getString(responseTypes[0])) {
			return false;
		}
		return true;
	}

	/**
	 * OPTIONAL. Kind of the application. The default, if omitted, is web. The defined values are native or web.
	 * Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as
	 * redirect_uris; they MUST NOT use localhost as the hostname.
	 * Native Clients MUST only register redirect_uris using custom URI schemes or URLs using the http:
	 * scheme with localhost as the hostname. Authorization Servers MAY place additional constraints
	 * on Native Clients. Authorization Servers MAY reject Redirection URI values using the http scheme,
	 * other than the localhost case for Native Clients. The Authorization Server MUST verify that all
	 * the registered redirect_uris conform to these constraints. This prevents sharing a Client ID across
	 * different types of Clients.
	 * @return
	 */
	protected getApplicationType(): string {
		if ("application_type" in this.client) {
			return OIDFJSON.getString(this.client["application_type"]);
		}
		return "web";
	}

	protected isApplicationTypeWeb(): boolean {
		return "web" === this.getApplicationType();
	}

	protected isApplicationTypeNative(): boolean {
		return "native" === this.getApplicationType();
	}

	/**
	 * OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Types that the Client is
	 * declaring that it will restrict itself to using. The Grant Type values used by OpenID Connect are:
	 * authorization_code: The Authorization Code Grant Type described in OAuth 2.0 Section 4.1.
	 * implicit: The Implicit Grant Type described in OAuth 2.0 Section 4.2.
	 * refresh_token: The Refresh Token Grant Type described in OAuth 2.0 Section 6.
	 * The following table lists the correspondence between response_type values that the Client will
	 * use and grant_type values that MUST be included in the registered grant_types list:
	 *   - code: authorization_code
	 *   - id_token: implicit
	 *   - token id_token: implicit
	 *   - code id_token: authorization_code, implicit
	 *   - code token: authorization_code, implicit
	 *   - code token id_token: authorization_code, implicit
	 * If omitted, the default is that the Client will use only the authorization_code Grant Type.
	 * @return
	 */
	protected getGrantTypes(): JsonArray {
		if ("grant_types" in this.client) {
			return getAsJsonArray(this.client["grant_types"]);
		}
		const defaultValue: JsonArray = [];
		defaultValue.push("authorization_code");
		return defaultValue;
	}

	/**
	 * OPTIONAL. Array of e-mail addresses of people responsible for this Client. This might be used by some
	 * providers to enable a Web user interface to modify the Client information.
	 * @return
	 */
	protected getContacts(): JsonArray | null {
		if ("contacts" in this.client) {
			return getAsJsonArray(this.client["contacts"]);
		}
		return null;
	}

	/**
	 * OPTIONAL. Name of the Client to be presented to the End-User. If desired, representation of this Claim in
	 * different languages and scripts is represented as described in Section 2.1.
	 * @param lang
	 * @return
	 */
	protected getClientName(lang: string | null): string | null {
		return this.getLocalizedString("client_name", lang);
	}

	/**
	 * OPTIONAL. URL that references a logo for the Client application. If present, the server SHOULD display this
	 * image to the End-User during approval. The value of this field MUST point to a valid image file.
	 * If desired, representation of this Claim in different languages and scripts is represented as
	 * described in Section 2.1.
	 * @param lang
	 * @return
	 */
	protected getLogoUri(lang: string | null): string | null {
		return this.getLocalizedString("logo_uri", lang);
	}

	/**
	 * key is lang (empty string for the default one without a lang)
	 * value is the uri
	 * @return
	 */
	protected getAllLogoUris(): Map<string, string> {
		return this.getAllLocalized("logo_uri");
	}

	/**
	 * OPTIONAL. URL of the home page of the Client. The value of this field MUST point to a valid Web page.
	 * If present, the server SHOULD display this URL to the End-User in a followable fashion.
	 * If desired, representation of this Claim in different languages and scripts is represented as
	 * described in Section 2.1.
	 * @param lang
	 * @return
	 */
	protected getClientUri(lang: string | null): string | null {
		return this.getLocalizedString("client_uri", lang);
	}

	/**
	 * key is lang (empty string for the default one without a lang)
	 * value is the uri
	 * @return
	 */
	protected getAllClientUris(): Map<string, string> {
		return this.getAllLocalized("client_uri");
	}

	/**
	 * OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the
	 * how the profile data will be used. The value of this field MUST point to a valid web
	 * page. The OpenID Provider SHOULD display this URL to the End-User if it is given.
	 * If desired, representation of this Claim in different languages and scripts is represented
	 * as described in Section 2.1.
	 * @param lang
	 * @return
	 */
	protected getPolicyUri(lang: string | null): string | null {
		return this.getLocalizedString("policy_uri", lang);
	}

	/**
	 * key is lang (empty string for the default one without a lang)
	 * value is the uri
	 * @return
	 */
	protected getAllPolicyUris(): Map<string, string> {
		return this.getAllLocalized("policy_uri");
	}

	/**
	 * OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the
	 * Relying Party's terms of service. The value of this field MUST point to a valid web page.
	 * The OpenID Provider SHOULD display this URL to the End-User if it is given.
	 * If desired, representation of this Claim in different languages and scripts is represented
	 * as described in Section 2.1.
	 * @param lang
	 * @return
	 */
	protected getTosUri(lang: string | null): string | null {
		return this.getLocalizedString("tos_uri", lang);
	}

	/**
	 * key is lang (empty string for the default one without a lang)
	 * value is the uri
	 * @return
	 */
	protected getAllTosUris(): Map<string, string> {
		return this.getAllLocalized("tos_uri");
	}

	/**
	 * Shared body of the Java getClientName/getLogoUri/getClientUri/getPolicyUri/getTosUri methods
	 * (identical code duplicated per member upstream).
	 */
	private getLocalizedString(name: string, lang: string | null): string | null {
		if (lang == null) {
			if (name in this.client) {
				return OIDFJSON.getString(this.client[name]);
			}
		} else if (name + "#" + lang in this.client) {
			return OIDFJSON.getString(this.client[name + "#" + lang]);
		}
		return null;
	}

	/**
	 * Shared body of the Java getAllLogoUris/getAllClientUris/getAllPolicyUris/getAllTosUris methods
	 * (identical code duplicated per member upstream). Insertion ordered like the Java LinkedHashMap.
	 */
	private getAllLocalized(name: string): Map<string, string> {
		const uris = new Map<string, string>();
		for (const key of Object.keys(this.client)) {
			if (key === name) {
				uris.set("", OIDFJSON.getString(this.client[key]));
			} else if (key.startsWith(name + "#")) {
				uris.set(key.substring((name + "#").length), OIDFJSON.getString(this.client[key]));
			}
		}
		return uris;
	}

	/**
	 * OPTIONAL. URL for the Client's JSON Web Key Set [JWK] document. If the Client signs
	 * requests to the Server, it contains the signing key(s) the Server uses to validate
	 * signatures from the Client. The JWK Set MAY also contain the Client's encryption keys(s),
	 * which are used by the Server to encrypt responses to the Client. When both signing and
	 * encryption keys are made available, a use (Key Use) parameter value is REQUIRED
	 * for all keys in the referenced JWK Set to indicate each key's intended usage.
	 * Although some algorithms allow the same key to be used for both signatures and encryption,
	 * doing so is NOT RECOMMENDED, as it is less secure.
	 * The JWK x5c parameter MAY be used to provide X.509 representations of keys provided.
	 * When used, the bare key values MUST still be present and MUST match those in the certificate.
	 * @return
	 */
	protected getJwksUri(): string | null {
		return this.getOptionalString("jwks_uri");
	}

	/**
	 * jwks
	 * OPTIONAL. Client's JSON Web Key Set [JWK] document, passed by value.
	 * The semantics of the jwks parameter are the same as the jwks_uri parameter,
	 * other than that the JWK Set is passed by value, rather than by reference.
	 * This parameter is intended only to be used by Clients that, for some reason,
	 * are unable to use the jwks_uri parameter, for instance, by native applications
	 * that might not have a location to host the contents of the JWK Set. If a Client
	 * can use jwks_uri, it MUST NOT use jwks. One significant downside of jwks is that
	 * it does not enable key rotation (which jwks_uri does, as described in Section 10
	 * of OpenID Connect Core 1.0 [OpenID.Core]). The jwks_uri and jwks parameters MUST
	 * NOT be used together.
	 * @return
	 */
	protected getJwks(): string | null {
		// UPSTREAM: jwks is a JSON object, OIDFJSON.getString throws if it is present
		return this.getOptionalString("jwks");
	}

	/**
	 * OPTIONAL. URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP.
	 * The URL references a file with a single JSON array of redirect_uri values. Please see Section 5.
	 * Providers that use pairwise sub (subject) values SHOULD utilize the sector_identifier_uri value
	 * provided in the Subject Identifier calculation for pairwise identifiers
	 * @return
	 */
	protected getSectorIdentifierUri(): string | null {
		return this.getOptionalString("sector_identifier_uri");
	}

	/**
	 * OPTIONAL. subject_type requested for responses to this Client. The subject_types_supported
	 * Discovery parameter contains a list of the supported subject_type values for this server.
	 * Valid types include pairwise and public.
	 * @return
	 */
	protected getSubjectType(): string | null {
		return this.getOptionalString("subject_type");
	}

	/**
	 * OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client.
	 * The value none MUST NOT be used as the ID Token alg value unless the Client uses only Response
	 * Types that return no ID Token from the Authorization Endpoint (such as when only using the
	 * Authorization Code Flow).
	 * The default, if omitted, is RS256.
	 * The public key for validating the signature is provided by retrieving the JWK Set referenced
	 * by the jwks_uri element from OpenID Connect Discovery 1.0 [OpenID.Discovery].
	 * @return
	 */
	protected getIdTokenSignedResponseAlg(): string {
		if ("id_token_signed_response_alg" in this.client) {
			return OIDFJSON.getString(this.client["id_token_signed_response_alg"]);
		}
		return "RS256";
	}

	/**
	 * OPTIONAL. JWE alg algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client.
	 * If this is requested, the response will be signed then encrypted, with the result being a
	 * Nested JWT, as defined in [JWT]. The default, if omitted, is that no encryption is performed.
	 * @return
	 */
	protected getIdTokenEncryptedResponseAlg(): string | null {
		return this.getOptionalString("id_token_encrypted_response_alg");
	}

	/**
	 * OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client.
	 * If id_token_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
	 * When id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also
	 * be provided.
	 * @return
	 */
	protected getIdTokenEncryptedResponseEnc(): string | null {
		if ("id_token_encrypted_response_enc" in this.client) {
			return OIDFJSON.getString(this.client["id_token_encrypted_response_enc"]);
		}
		if (this.getIdTokenEncryptedResponseAlg() != null) {
			return "A128CBC-HS256";
		}
		return null;
	}

	/**
	 * OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified,
	 * the response will be JWT [JWT] serialized, and signed using JWS. The default, if omitted, is for
	 * the UserInfo Response to return the Claims as a UTF-8 encoded JSON object using the
	 * application/json content-type.
	 * @return
	 */
	protected getUserinfoSignedResponseAlg(): string | null {
		return this.getOptionalString("userinfo_signed_response_alg");
	}

	/**
	 * OPTIONAL. JWE [JWE] alg algorithm [JWA] REQUIRED for encrypting UserInfo Responses.
	 * If both signing and encryption are requested, the response will be signed then encrypted,
	 * with the result being a Nested JWT, as defined in [JWT]. The default, if omitted, is that
	 * no encryption is performed.
	 * @return
	 */
	protected getUserinfoEncryptedResponseAlg(): string | null {
		return this.getOptionalString("userinfo_encrypted_response_alg");
	}

	/**
	 * OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting UserInfo Responses. If
	 * userinfo_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
	 * When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST also
	 * be provided.
	 * @return
	 */
	protected getUserinfoEncryptedResponseEnc(): string | null {
		if ("userinfo_encrypted_response_enc" in this.client) {
			return OIDFJSON.getString(this.client["userinfo_encrypted_response_enc"]);
		}
		if (this.getUserinfoEncryptedResponseAlg() != null) {
			return "A128CBC-HS256";
		}
		return null;
	}

	/**
	 * OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP.
	 * All Request Objects from this Client MUST be rejected, if not signed with this algorithm.
	 * Request Objects are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core].
	 * This algorithm MUST be used both when the Request Object is passed by value (using the request parameter)
	 * and when it is passed by reference (using the request_uri parameter).
	 * Servers SHOULD support RS256. The value none MAY be used.
	 * The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
	 * @return
	 */
	protected getRequestObjectSigningAlg(): string | null {
		return this.getOptionalString("request_object_signing_alg");
	}

	/**
	 * OPTIONAL. JWE [JWE] alg algorithm [JWA] the RP is declaring that it may use for encrypting
	 * Request Objects sent to the OP. This parameter SHOULD be included when symmetric encryption
	 * will be used, since this signals to the OP that a client_secret value needs to be returned
	 * from which the symmetric key will be derived, that might not otherwise be returned.
	 * The RP MAY still use other supported encryption algorithms or send unencrypted Request Objects,
	 * even when this parameter is present. If both signing and encryption are requested,
	 * the Request Object will be signed then encrypted, with the result being a Nested JWT,
	 * as defined in [JWT]. The default, if omitted, is that the RP is not declaring whether
	 * it might encrypt any Request Objects.
	 * @return
	 */
	protected getRequestObjectEncryptionAlg(): string | null {
		return this.getOptionalString("request_object_encryption_alg");
	}

	/**
	 * OPTIONAL. JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting
	 * Request Objects sent to the OP. If request_object_encryption_alg is specified, the default
	 * for this value is A128CBC-HS256. When request_object_encryption_enc is included,
	 * request_object_encryption_alg MUST also be provided.
	 * @return
	 */
	protected getRequestObjectEncryptionEnc(): string | null {
		if ("request_object_encryption_enc" in this.client) {
			return OIDFJSON.getString(this.client["request_object_encryption_enc"]);
		}
		if (this.getRequestObjectEncryptionAlg() != null) {
			return "A128CBC-HS256";
		}
		return null;
	}

	/**
	 * OPTIONAL. Requested Client Authentication method for the Token Endpoint. The options are
	 * client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt, and none, as
	 * described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core]. Other authentication
	 * methods MAY be defined by extensions. If omitted, the default is client_secret_basic
	 * -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
	 * @return
	 */
	protected getTokenEndpointAuthMethod(): string | null {
		return this.getOptionalString("token_endpoint_auth_method");
	}

	/**
	 * OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing the JWT [JWT] used
	 * to authenticate the Client at the Token Endpoint for the private_key_jwt and
	 * client_secret_jwt authentication methods. All Token Requests using these authentication
	 * methods from this Client MUST be rejected, if the JWT is not signed with this algorithm.
	 * Servers SHOULD support RS256. The value none MUST NOT be used. The default, if omitted,
	 * is that any algorithm supported by the OP and the RP MAY be used.
	 * @return
	 */
	protected getTokenEndpointAuthSigningAlg(): string | null {
		return this.getOptionalString("token_endpoint_auth_signing_alg");
	}

	/**
	 * OPTIONAL. Default Maximum Authentication Age. Specifies that the End-User MUST be actively
	 * authenticated if the End-User was authenticated longer ago than the specified number of
	 * seconds. The max_age request parameter overrides this default value. If omitted, no default
	 * Maximum Authentication Age is specified.
	 * @return
	 */
	protected getDefaultMaxAge(): number | null {
		if ("default_max_age" in this.client) {
			return OIDFJSON.getNumber(this.client["default_max_age"]);
		}
		return null;
	}

	/**
	 * OPTIONAL. Boolean value specifying whether the auth_time Claim in the ID Token is REQUIRED.
	 * It is REQUIRED when the value is true.
	 * (If this is false, the auth_time Claim can still be dynamically requested as an individual
	 * Claim for the ID Token using the claims request parameter described in Section 5.5.1 of
	 * OpenID Connect Core 1.0 [OpenID.Core].)
	 * If omitted, the default value is false.
	 * @return
	 */
	protected getRequireAuthTime(): boolean | null {
		if ("require_auth_time" in this.client) {
			return OIDFJSON.getBoolean(this.client["require_auth_time"]);
		}
		return null;
	}

	/**
	 * OPTIONAL. Default requested Authentication Context Class Reference values. Array of strings
	 * that specifies the default acr values that the OP is being requested to use for processing
	 * requests from this Client, with the values appearing in order of preference.
	 * The Authentication Context Class satisfied by the authentication performed is returned as
	 * the acr Claim Value in the issued ID Token. The acr Claim is requested as a Voluntary Claim
	 * by this parameter. The acr_values_supported discovery element contains a list of the supported
	 * acr values supported by this server. Values specified in the acr_values request parameter or
	 * an individual acr Claim request override these default values.
	 * @return
	 */
	protected getDefaultAcrValues(): JsonArray | null {
		if ("default_acr_values" in this.client) {
			return getAsJsonArray(this.client["default_acr_values"]);
		}

		return null;
	}

	/**
	 * OPTIONAL. URI using the https scheme that a third party can use to initiate a login by the RP,
	 * as specified in Section 4 of OpenID Connect Core 1.0 [OpenID.Core].
	 * The URI MUST accept requests via both GET and POST.
	 * The Client MUST understand the login_hint and iss parameters and SHOULD support the
	 * target_link_uri parameter.
	 * @return
	 */
	protected getInitiateLoginUri(): string | null {
		return this.getOptionalString("initiate_login_uri");
	}

	/**
	 * OPTIONAL. Array of request_uri values that are pre-registered by the RP for use at the OP.
	 * Servers MAY cache the contents of the files referenced by these URIs and not retrieve them
	 * at the time they are used in a request. OPs can require that request_uri values used be
	 * pre-registered with the require_request_uri_registration discovery parameter.
	 * If the contents of the request file could ever change, these URI values SHOULD include the
	 * base64url encoded SHA-256 hash value of the file contents referenced by the URI as the value
	 * of the URI fragment. If the fragment value used for a URI changes, that signals the server
	 * that its cached value for that URI with the old fragment value is no longer valid.
	 * @return
	 */
	protected getRequestUris(): JsonArray | null {
		if ("request_uris" in this.client) {
			return getAsJsonArray(this.client["request_uris"]);
		}
		return null;
	}

	/** Shared body of the Java `if(client.has(k)) return OIDFJSON.getString(client.get(k)); return null;` getters */
	private getOptionalString(name: string): string | null {
		if (name in this.client) {
			return OIDFJSON.getString(this.client[name]);
		}
		return null;
	}
}

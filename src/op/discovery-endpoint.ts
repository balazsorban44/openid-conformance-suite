/**
 * The discovery endpoint verification (upstream OIDCCDiscoveryEndpointVerification): the checks on the OP's
 * metadata document - the discovery URL and issuer, the metadata schema, the required OpenID Connect metadata and
 * the optional parameters certification looks at.
 *
 *   const { metadata, response } = await getDynamicServerConfiguration(config);
 *   soft(() => ensureDiscoveryEndpointResponseStatusCodeIs200(response, "OIDCD-4"));
 *   ...
 *   await performEndpointVerification({ metadata, config, variant });
 */
import { condition, skipped, skippedWithResult, soft, type Condition } from "../suite/conditions.ts";
import type { TestConfig } from "../suite/config.ts";
import { validateSubtags, nonCanonicalCasing, subtagRegistry } from "../suite/bcp47.ts";
import { JsonSchemaValidation, JsonSchemaValidationException, toInstancePropertyPath } from "../suite/json-schema.ts";
import {
	checkDiscEndpointAllEndpointsAreHttps,
	checkDiscEndpointRequestParameterSupported,
	checkDiscEndpointRequestUriParameterSupported,
	validateJsonArray,
	validateJsonBoolean,
	validateJsonUriIsHttps,
	type ServerMetadata,
} from "./discovery.ts";
import { fetchServerKeys, validateJwks } from "./jwks.ts";
import type { OpVariant } from "./op.ts";
import { SUPPORT_EMAIL } from "./registration.ts";

const NEW_ISSUE_URL = "https://github.com/balazsorban44/openid-conformance-suite/issues/new";
const METADATA_SCHEMA = "json-schemas/rfc8414/oauth_authorization_server_metadata.json";

function serverConfig(config: TestConfig): Record<string, unknown> {
	return (config.server ?? {}) as Record<string, unknown>;
}

/** upstream: condition/client/CheckDiscEndpointDiscoveryUrl.java */
export function checkDiscEndpointDiscoveryUrl(config: TestConfig, ...requirements: string[]): void {
	const c: Condition = condition("CheckDiscEndpointDiscoveryUrl", ...requirements);
	const requiredProtocol = "https";
	const configUrl = serverConfig(config)["discoveryUrl"];
	if (configUrl == null) {
		c.failure("Unable to find Discovery URL", { "No discoveryUrl": config });
	}
	if (typeof configUrl === "object") {
		c.failure("Specified value is not a Json primitive", { Failure: configUrl });
	}
	const discoveryUrl = String(configUrl);
	let url: URL;
	try {
		url = new URL(discoveryUrl);
	} catch {
		return c.failure("Invalid URL. Unable to parse.", { Failure: configUrl });
	}
	if (!url.pathname.endsWith("/.well-known/openid-configuration")) {
		c.failure("discoveryUrl is missing '/.well-known/openid-configuration'", { actual: discoveryUrl });
	}
	// Java's URL.getProtocol() has no trailing colon
	const protocol = url.protocol.replace(/:$/, "");
	if (protocol !== requiredProtocol) {
		c.failure("Expected " + requiredProtocol + " protocol for server.discoveryUrl", {
			actual: protocol,
			expected: requiredProtocol,
		});
	}
	c.success("discoveryUrl", { actual: configUrl });
}

function removeSlash(url: string): string {
	return url.endsWith("/") ? url.substring(0, url.length - 1) : url;
}

/** upstream: condition/client/CheckDiscEndpointIssuer.java */
export function checkDiscEndpointIssuer(metadata: ServerMetadata, config: TestConfig, ...requirements: string[]): void {
	const c: Condition = condition("CheckDiscEndpointIssuer", ...requirements);
	const issuerElement = metadata.issuer as unknown;
	if (issuerElement == null || (typeof issuerElement === "object" && !Array.isArray(issuerElement))) {
		c.failure("issuer is missing from discovery endpoint document");
	}
	if (typeof issuerElement !== "string") {
		// UPSTREAM: OIDFJSON.getString throws for anything but a string
		throw new TypeError("getString called on something that is not a string: " + JSON.stringify(issuerElement));
	}
	const issuerUrl = issuerElement;
	let discoveryUrl = String(serverConfig(config)["discoveryUrl"]);
	const removingPartInUrl = ".well-known/openid-configuration";
	if (discoveryUrl.endsWith(removingPartInUrl)) {
		discoveryUrl = discoveryUrl.substring(0, discoveryUrl.length - removingPartInUrl.length);
	}
	// Remove slash character endpoint url before comparing
	if (removeSlash(issuerUrl) !== removeSlash(discoveryUrl)) {
		c.failure(
			"issuer listed in the discovery document is not consistent with the location the discovery document was retrieved from. These must match to prevent impersonation attacks.",
			{ discovery_url: discoveryUrl, issuer: issuerUrl },
		);
	}
	c.success("issuer is consistent with the discovery endpoint", { issuer: issuerUrl });
}

// RFC 3986 appendix B
const URI_PATTERN = /^(?:([^:/?#]+):)?(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/s;
const HOSTNAME_PATTERN = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.?$/;
const IPV4_PATTERN = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV6_PATTERN = /^\[[0-9A-Fa-f:.]+\]$/;

/**
 * An RFC 8414 §2 issuer identifier URL: a syntactically valid URI using the https scheme (case-insensitive), with a
 * host, and no fragment, query, userinfo or out-of-range port. Appends one issue per problem to `issues`.
 *
 * Port of upstream's condition/util/IssuerUrlValidation. UPSTREAM: Java uses java.net.URI, whose parser has no
 * equivalent in JavaScript (WHATWG URL normalises and rejects different things): the RFC 3986 appendix B
 * decomposition plus java.net.URI's character and server-based authority rules are reimplemented; the wording of
 * the "is not a valid URI" detail differs from Java's URISyntaxException message.
 */
function validateIssuerUrl(value: string, label: string, issues: string[]): void {
	const syntaxError = uriSyntaxError(value);
	if (syntaxError != null) {
		issues.push(`${label}: '${value}' is not a valid URI (${syntaxError})`);
		return;
	}
	const m = URI_PATTERN.exec(value) as RegExpExecArray;
	const scheme = m[1];
	const query = m[4];
	const fragment = m[5];
	const { host, userInfo, port } = parseAuthority(m[2]);
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
	// URI.getPort() returns -1 when absent or a non-negative int otherwise, so only the upper bound can be violated
	if (port > 65535) {
		issues.push(`${label}: '${value}' contains an out-of-range port (${port})`);
	}
}

/** Approximation of the checks java.net.URI's parser performs; null if the string is a valid URI */
function uriSyntaxError(value: string): string | null {
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
	const m = URI_PATTERN.exec(value);
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
function parseAuthority(authority: string | undefined): { host: string | null; userInfo: string | null; port: number } {
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
	if (!HOSTNAME_PATTERN.test(hostPart) && !IPV4_PATTERN.test(hostPart) && !IPV6_PATTERN.test(hostPart)) {
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

/** upstream: condition/client/CheckDiscEndpointIssuerIsValidUrl.java */
export function checkDiscEndpointIssuerIsValidUrl(metadata: ServerMetadata, ...requirements: string[]): void {
	const c: Condition = condition("CheckDiscEndpointIssuerIsValidUrl", ...requirements);
	const issuer = metadata.issuer as unknown;
	if (typeof issuer !== "string") {
		c.failure("issuer is missing or not a string in the authorization server metadata", { issuer: issuer ?? null });
	}
	const issues: string[] = [];
	validateIssuerUrl(issuer, "issuer", issues);
	if (issues.length > 0) {
		c.failure("issuer is not a valid RFC 8414 issuer identifier URL", { issuer, issues });
	}
	c.success("issuer is a valid issuer identifier URL", { issuer });
}

/** upstream: condition/client/ValidateServerMetadataAgainstSchema.java (AbstractJsonSchemaBasedValidation) */
export function validateServerMetadataAgainstSchema(metadata: ServerMetadata, ...requirements: string[]): void {
	const c: Condition = condition("ValidateServerMetadataAgainstSchema", ...requirements);
	const inputName = "OAuth Authorization Server metadata";
	const validation = new JsonSchemaValidation(METADATA_SCHEMA);
	// structural errors only: unknown properties are CheckForUnexpectedParametersInServerMetadata's warning
	validation.setIgnoreUnknownPropertyStrictness(true);
	const result = validation.validate(metadata as never);
	if (!result.isValid()) {
		c.failureFrom(
			"Found invalid entries in " + inputName + " input",
			new JsonSchemaValidationException("Schema Validation Failed", result),
			{ invalid_entries: result.getPropertyErrors(), input: metadata, schema_link: "/" + METADATA_SCHEMA },
		);
	}
	c.success(inputName + " input is valid", { input: metadata, schema_link: "/" + METADATA_SCHEMA });
}

/**
 * Unknown properties in the metadata; `server.allow_unexpected_metadata_fields` in the configuration lists
 * extension names to accept.
 *
 * upstream: condition/client/CheckForUnexpectedParametersInServerMetadata.java (AbstractCheckForUnexpectedSchemaProperties)
 */
export function checkForUnexpectedParametersInServerMetadata(
	metadata: ServerMetadata,
	config: TestConfig,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckForUnexpectedParametersInServerMetadata", ...requirements);
	const inputName = "OAuth Authorization Server metadata";
	const configKey = "server.allow_unexpected_metadata_fields";
	const schemaLink = "/" + METADATA_SCHEMA;
	const noUnknown = () =>
		c.success("No unknown properties were found in the " + inputName, { input: metadata, schema_link: schemaLink });
	const result = new JsonSchemaValidation(METADATA_SCHEMA).validate(metadata as never);
	if (result.isValid()) {
		noUnknown();
		return;
	}
	const allowed = serverConfig(config)["allow_unexpected_metadata_fields"];
	const ignored = new Set<string>(
		Array.isArray(allowed) ? allowed.filter((a) => a == null || typeof a !== "object").map(String) : [],
	);
	const unknownProps: Record<string, unknown>[] = [];
	const allowListed: string[] = [];
	for (const msg of result.unknownPropertyErrors().getValidationMessages()) {
		const path = toInstancePropertyPath(msg.getInstanceLocation(), msg.getProperty());
		if (ignored.has(msg.getProperty() as string)) {
			allowListed.push(path);
			continue;
		}
		unknownProps.push({ property: msg.getProperty(), path });
	}
	if (unknownProps.length === 0) {
		if (allowListed.length === 0) {
			noUnknown();
		} else {
			c.success(
				"The only unknown properties found in the " +
					inputName +
					" are allow-listed in the '" +
					configKey +
					"' array in the test configuration",
				{ allow_listed_properties: allowListed, input: metadata, schema_link: schemaLink },
			);
		}
		return;
	}
	c.failure(
		"Unknown properties were found in the " +
			inputName +
			". This may indicate the sender has misunderstood the spec, or it may be using extensions the test suite is unaware of." +
			" If these are known extensions, add their names to the '" +
			configKey +
			"' array in the test configuration to suppress this warning." +
			" If they are derived from a specification, please open an issue at " +
			NEW_ISSUE_URL +
			" (or, if you are unable to, email " +
			SUPPORT_EMAIL +
			") so the test suite can be updated.",
		{ unknown_properties: unknownProps, input: metadata, schema_link: schemaLink },
	);
}

/** upstream: condition/client/CheckDiscEndpointAuthorizationEndpoint.java */
export function checkDiscEndpointAuthorizationEndpoint(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonUriIsHttps(
		condition("CheckDiscEndpointAuthorizationEndpoint", ...requirements),
		metadata,
		"authorization_endpoint",
	);
}

/** upstream: condition/client/CheckDiscEndpointTokenEndpoint.java */
export function checkDiscEndpointTokenEndpoint(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonUriIsHttps(condition("CheckDiscEndpointTokenEndpoint", ...requirements), metadata, "token_endpoint");
}

/** upstream: condition/client/CheckDiscEndpointUserinfoEndpoint.java */
export function checkDiscEndpointUserinfoEndpoint(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonUriIsHttps(
		condition("CheckDiscEndpointUserinfoEndpoint", ...requirements),
		metadata,
		"userinfo_endpoint",
	);
}

/** upstream: condition/client/CheckDiscEndpointRegistrationEndpoint.java */
export function checkDiscEndpointRegistrationEndpoint(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonUriIsHttps(
		condition("CheckDiscEndpointRegistrationEndpoint", ...requirements),
		metadata,
		"registration_endpoint",
	);
}

/** upstream: condition/client/CheckJwksUri.java */
export function checkJwksUri(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonUriIsHttps(condition("CheckJwksUri", ...requirements), metadata, "jwks_uri");
}

/** upstream: condition/client/CheckDiscEndpointClaimsParameterSupported.java */
export function checkDiscEndpointClaimsParameterSupported(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonBoolean(
		condition("CheckDiscEndpointClaimsParameterSupported", ...requirements),
		metadata,
		"claims_parameter_supported",
		false,
		true,
	);
}

/** upstream: AbstractValidateResponseTypesArray.elementsEqual: response types are equal as sets of values */
function responseTypesEqual(e1: string, e2: string): boolean {
	// UPSTREAM: Java Set.of(...) throws IllegalArgumentException on duplicate elements (e.g. "code code"); not replicated
	const s1 = new Set(e1.split(" "));
	const s2 = new Set(e2.split(" "));
	return s1.size === s2.size && [...s1].every((v) => s2.has(v));
}

/** upstream: condition/client/CheckDiscEndpointSubjectTypesSupported.java */
export function checkDiscEndpointSubjectTypesSupported(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonArray(
		condition("CheckDiscEndpointSubjectTypesSupported", ...requirements),
		metadata,
		"subject_types_supported",
		["public", "pairwise"],
		1,
		"subject_types_supported is required to contain at least one of public or pairwise",
	);
}

/** upstream: condition/client/CheckDiscEndpointScopesSupportedContainsOpenId.java */
export function checkDiscEndpointScopesSupportedContainsOpenId(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonArray(
		condition("CheckDiscEndpointScopesSupportedContainsOpenId", ...requirements),
		metadata,
		"scopes_supported",
		["openid"],
		1,
		"scopes_supported in the server's discovery document does not contain 'openid'.",
	);
}

/** upstream: condition/client/OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported.java */
export function oidccCheckDiscEndpointIdTokenSigningAlgValuesSupported(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonArray(
		condition("OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported", ...requirements),
		metadata,
		"id_token_signing_alg_values_supported",
		["RS256"],
		1,
		"RS256 support is required, but the server does not list it in id_token_signing_alg_values_supported",
	);
}

/** upstream: condition/client/OIDCCCheckDiscEndpointResponseTypesSupported.java */
export function oidccCheckDiscEndpointResponseTypesSupported(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonArray(
		condition("OIDCCCheckDiscEndpointResponseTypesSupported", ...requirements),
		metadata,
		"response_types_supported",
		["code", "code id_token", "id_token", "token id_token", "code id_token token", "code token"],
		1,
		"The server must support at least one of the response types defined in OpenID Connect.",
		responseTypesEqual,
	);
}

/** upstream: condition/client/OIDCCCheckDiscEndpointResponseTypesSupportedDynamic.java */
export function oidccCheckDiscEndpointResponseTypesSupportedDynamic(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonArray(
		condition("OIDCCCheckDiscEndpointResponseTypesSupportedDynamic", ...requirements),
		metadata,
		"response_types_supported",
		["code", "id_token", "token id_token"],
		3,
		"The server does not support all of the mandatory to implement response_types for dynamic OpenID Providers.",
		responseTypesEqual,
	);
}

/** upstream: condition/client/OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported.java */
export function oidccCheckDiscEndpointUserinfoSigningAlgValuesSupported(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	// there are no required values ("none" MAY be included): only the checks for being an array apply
	validateJsonArray(
		condition("OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported", ...requirements),
		metadata,
		"userinfo_signing_alg_values_supported",
		[],
		0,
		null,
	);
}

/** upstream: condition/client/OIDCCCheckDiscEndpointClaimsSupported.java */
export function oidccCheckDiscEndpointClaimsSupported(metadata: ServerMetadata, ...requirements: string[]): void {
	// there are no required values ("none" MAY be included): only the checks for being an array apply
	validateJsonArray(
		condition("OIDCCCheckDiscEndpointClaimsSupported", ...requirements),
		metadata,
		"claims_supported",
		[],
		0,
		null,
	);
}

/** upstream: condition/client/OIDCCCheckDiscEndpointGrantTypesSupported.java */
export function oidccCheckDiscEndpointGrantTypesSupported(metadata: ServerMetadata, ...requirements: string[]): void {
	const c: Condition = condition("OIDCCCheckDiscEndpointGrantTypesSupported", ...requirements);
	const key = "grant_types_supported";
	const grantTypesSupported = metadata[key];
	if (grantTypesSupported == null) {
		c.success(key + " not present in server configuration (so will default to authorization_code and implicit).");
		return;
	}
	if (!Array.isArray(grantTypesSupported)) {
		c.failure(key + " in discovery document, if present, must be an array.", { [key]: grantTypesSupported });
	}
	if (grantTypesSupported.length === 0) {
		c.failure(key + " in discovery document must not be an empty array.");
	}
	c.success(key + " is a non-empty array.", { [key]: grantTypesSupported });
}

/** upstream: condition/client/OIDCCCheckDiscEndpointGrantTypesSupportedDynamic.java */
export function oidccCheckDiscEndpointGrantTypesSupportedDynamic(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	const c: Condition = condition("OIDCCCheckDiscEndpointGrantTypesSupportedDynamic", ...requirements);
	const key = "grant_types_supported";
	if (metadata[key] === undefined) {
		c.success(
			"server discovery document does not contain " +
				key +
				", so by default authorization_code and implicit are supported",
		);
		return;
	}
	validateJsonArray(
		c,
		metadata,
		key,
		["authorization_code", "implicit"],
		2,
		"Servers certifying for the 'dynamic' certification profile are required to support the grant types 'authorization_code' and 'implicit'.",
	);
}

/** upstream: condition/client/CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256.java */
export function checkDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonArray(
		condition("CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256", ...requirements),
		metadata,
		"request_object_signing_alg_values_supported",
		["RS256"],
		1,
		"The server does not support RS256; this is a 'should' in https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata - note that support for 'none' (unsigned request objects) is not required as use of this is discouraged in many circumstances, see https://gitlab.com/openid/conformance-suite/-/issues/826",
	);
}

/** upstream: condition/client/EnsureServerConfigurationCodeChallengeMethodsSupportedIsAnArray.java */
export function ensureServerConfigurationCodeChallengeMethodsSupportedIsAnArray(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureServerConfigurationCodeChallengeMethodsSupportedIsAnArray", ...requirements);
	const key = "code_challenge_methods_supported";
	const serverValues = metadata[key];
	// For OIDC there is no requirement to support PKCE. Thus a missing claim or a claim with an empty array value is valid.
	if (serverValues === undefined) {
		c.success(key + " is not present in the discovery document");
		return;
	}
	if (Array.isArray(serverValues) && serverValues.length === 0) {
		c.success(key + " is an empty array");
		return;
	}
	validateJsonArray(c, metadata, key, ["S256", "plain"], 1, "No matching value from server");
}

/**
 * Why `token` is not a valid RFC 6749 Appendix A.4 scope-token (`1*( %x21 / %x23-5B / %x5D-7E )`: visible ASCII
 * except space, double-quote and backslash), naming the offending character and its position; null when it is one.
 *
 * Port of upstream's condition/util/ScopeTokenSyntaxUtil (RFC6749AppendixASyntaxUtils.isNQChar).
 */
function scopeTokenSyntaxError(token: string | null | undefined): string | null {
	if (token == null || token === "") {
		return "is empty; an RFC 6749 Appendix A.4 scope-token must contain at least one character";
	}
	for (let i = 0; i < token.length; i++) {
		const c = token.charCodeAt(i);
		const nqChar = c === 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e);
		if (!nqChar) {
			return (
				`contains ${describeChar(c)} at index ${i}, which is not permitted by the RFC 6749 Appendix A.4 ` +
				"scope-token ABNF (allowed characters are %x21, %x23-5B and %x5D-7E: visible ASCII " +
				"except space, double-quote and backslash)"
			);
		}
	}
	return null;
}

function describeChar(c: number): string {
	const hex = (width: number) => c.toString(16).toUpperCase().padStart(width, "0");
	switch (c) {
		case 0x20:
			return "' ' (0x20 SPACE)";
		case 0x22:
			return "'\"' (0x22 DQUOTE)";
		case 0x5c:
			return "'\\' (0x5C BACKSLASH)";
		default:
			if (c < 0x20 || c === 0x7f) {
				return `0x${hex(2)} (control character)`;
			}
			if (c > 0x7e) {
				return `U+${hex(4)} (non-ASCII character)`;
			}
			return `'${String.fromCharCode(c)}' (0x${hex(2)})`;
	}
}

/** upstream: condition/client/CheckDiscEndpointScopesSupportedSyntax.java */
export function checkDiscEndpointScopesSupportedSyntax(metadata: ServerMetadata, ...requirements: string[]): void {
	const c: Condition = condition("CheckDiscEndpointScopesSupportedSyntax", ...requirements);
	const scopesSupported = metadata["scopes_supported"];
	if (scopesSupported == null) {
		c.success("authorization server metadata has no scopes_supported (OPTIONAL); nothing to validate");
		return;
	}
	if (!Array.isArray(scopesSupported)) {
		c.failure("scopes_supported is not a JSON array", { scopes_supported: scopesSupported });
	}
	const issues: string[] = [];
	scopesSupported.forEach((element, i) => {
		if (typeof element !== "string") {
			issues.push(`scopes_supported[${i}]: expected string, got ${JSON.stringify(element)}`);
			return;
		}
		const syntaxError = scopeTokenSyntaxError(element);
		if (syntaxError != null) {
			issues.push(`scopes_supported[${i}]: '${element}' ${syntaxError}`);
		}
	});
	if (issues.length > 0) {
		c.failure("Invalid scope syntax in authorization server scopes_supported", { issues });
	}
	c.success("All scopes_supported entries are valid RFC 6749 scope-tokens");
}

const LOCALE_FIELDS = ["ui_locales_supported", "claims_locales_supported"];

/** upstream: condition/client/CheckDiscEndpointLocalesSyntax.java */
export function checkDiscEndpointLocalesSyntax(metadata: ServerMetadata, ...requirements: string[]): void {
	const c: Condition = condition("CheckDiscEndpointLocalesSyntax", ...requirements);
	const issues: string[] = [];
	for (const fieldName of LOCALE_FIELDS) {
		const values = metadata[fieldName];
		if (values == null) {
			continue;
		}
		if (!Array.isArray(values)) {
			issues.push(`${fieldName}: expected JSON array, got ${JSON.stringify(values)}`);
			continue;
		}
		values.forEach((entry, i) => {
			if (typeof entry !== "string") {
				issues.push(`${fieldName}[${i}]: expected string, got ${JSON.stringify(entry)}`);
				return;
			}
			validateSubtags(entry, `${fieldName}[${i}]`, issues);
		});
	}
	if (issues.length > 0) {
		c.failure("Invalid BCP47 language tag(s) in authorization server metadata", {
			issues,
			language_subtag_registry_date: subtagRegistry().getFileDate(),
		});
	}
	c.success(
		"All ui_locales_supported / claims_locales_supported entries are well-formed BCP47 tags with registered subtags",
	);
}

/** upstream: condition/client/CheckDiscEndpointLocalesCanonicalCasing.java */
export function checkDiscEndpointLocalesCanonicalCasing(metadata: ServerMetadata, ...requirements: string[]): void {
	const c: Condition = condition("CheckDiscEndpointLocalesCanonicalCasing", ...requirements);
	const issues: string[] = [];
	for (const fieldName of LOCALE_FIELDS) {
		const values = metadata[fieldName];
		if (!Array.isArray(values)) {
			continue;
		}
		values.forEach((entry, i) => {
			if (typeof entry !== "string") {
				return;
			}
			const canonical = nonCanonicalCasing(entry);
			if (canonical != null) {
				issues.push(`${fieldName}[${i}]: '${entry}' should be '${canonical}' to match BCP47 canonical casing`);
			}
		});
	}
	if (issues.length > 0) {
		c.failure(
			"Authorization server locale tags deviate from BCP47 canonical casing (convention is lowercase language subtag, Title-case script, uppercase region); RFC 5646 §2.1.1 permits any case, but real-world implementations typically expect canonical casing.",
			{ issues },
		);
	}
	c.success("All ui_locales_supported / claims_locales_supported entries use canonical BCP47 casing");
}

/**
 * The checks of OIDCCDiscoveryEndpointVerification.performEndpointVerification, in upstream's order and severities
 * (the logout plans' discovery verification modules are separate classes upstream with their own few checks, in
 * src/op/discovery.ts).
 *
 * upstream: openid/OIDCCDiscoveryEndpointVerification.java + sequence/CheckRequiredOidcDiscoveryMetadataSequence.java
 */
export async function performEndpointVerification(op: {
	metadata: ServerMetadata;
	config: TestConfig;
	variant: Pick<OpVariant, "client_registration">;
}): Promise<void> {
	const { metadata, config } = op;
	const dynamic = op.variant.client_registration === "dynamic_client";
	soft(() => checkDiscEndpointDiscoveryUrl(config));

	soft(() => checkDiscEndpointIssuer(metadata, config, "OIDCD-4.3", "OIDCD-7.2"));
	soft(() => checkDiscEndpointIssuerIsValidUrl(metadata, "RFC8414-2"));

	soft(() => validateServerMetadataAgainstSchema(metadata, "OIDCD-3", "RFC8414-2"));
	soft(() => checkForUnexpectedParametersInServerMetadata(metadata, config, "OIDCD-3", "RFC8414-2"), "warning");

	// Includes verify-op-endpoints-use-https assertion (OIDC test) for each endpoint tested,
	// verify-id_token_signing-algorithm-is-supported and providerinfo-has-jwks_uri
	// upstream: CheckRequiredOidcDiscoveryMetadataSequence
	soft(() => checkDiscEndpointAuthorizationEndpoint(metadata, "OIDCD-3"));
	soft(() => checkDiscEndpointTokenEndpoint(metadata, "OIDCD-3"));
	soft(() => checkJwksUri(metadata, "OIDCD-3"));
	soft(() =>
		dynamic
			? oidccCheckDiscEndpointResponseTypesSupportedDynamic(metadata, "OIDCD-3", "OIDCC-15.2")
			: oidccCheckDiscEndpointResponseTypesSupported(metadata, "OIDCD-3", "OIDCC-3"),
	);
	soft(() => checkDiscEndpointSubjectTypesSupported(metadata, "OIDCD-3"));
	soft(() => oidccCheckDiscEndpointIdTokenSigningAlgValuesSupported(metadata, "OIDCD-3"));
	// scopes_supported is only RECOMMENDED, but an OpenID Provider that publishes it must list the openid scope
	if (metadata["scopes_supported"] == null) {
		skippedWithResult(
			"WARNING",
			"CheckDiscEndpointScopesSupportedContainsOpenId",
			{ element: ["server", "scopes_supported"] },
			"OIDCD-3",
		);
	} else {
		soft(() => checkDiscEndpointScopesSupportedContainsOpenId(metadata, "OIDCD-3"));
	}

	if (metadata["userinfo_signing_alg_values_supported"] == null) {
		skipped(
			"OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported",
			{ element: ["server", "userinfo_signing_alg_values_supported"] },
			"OIDCD-3",
		);
	} else {
		soft(() => oidccCheckDiscEndpointUserinfoSigningAlgValuesSupported(metadata, "OIDCD-3"));
	}

	if (metadata.userinfo_endpoint == null) {
		// userinfo endpoint is recommended in the spec
		skippedWithResult(
			"WARNING",
			"CheckDiscEndpointUserinfoEndpoint",
			{ element: ["server", "userinfo_endpoint"] },
			"OIDCD-3",
		);
	} else {
		soft(() => checkDiscEndpointUserinfoEndpoint(metadata, "OIDCD-3"));
	}

	// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#verify_op_has_registration_endpoint
	if (metadata.registration_endpoint == null) {
		skipped("CheckDiscEndpointRegistrationEndpoint", { element: ["server", "registration_endpoint"] }, "OIDCD-3");
	} else {
		soft(() => checkDiscEndpointRegistrationEndpoint(metadata, "OIDCD-3"));
	}

	const jwks = await fetchServerKeys(metadata);
	await validateJwks(jwks, "server JWKS", { requirements: ["OIDCD-3"] });

	soft(() => checkDiscEndpointRequestParameterSupported(metadata), "info");

	soft(() => checkDiscEndpointRequestUriParameterSupported(metadata), "info");

	if (metadata["request_object_signing_alg_values_supported"] == null) {
		skipped(
			"CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256",
			{ element: ["server", "request_object_signing_alg_values_supported"] },
			"OIDCD-3",
		);
	} else {
		soft(() => checkDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256(metadata, "OIDCD-3"), "warning");
	}

	soft(() => checkDiscEndpointClaimsParameterSupported(metadata, "OIDCD-3"), "info");

	// Includes providerinfo-has-claims_supported assertion (OIDC test)
	// claims_supported is recommended to be present, but not required
	soft(() => oidccCheckDiscEndpointClaimsSupported(metadata, "OIDCD-3"), "warning");

	soft(() =>
		dynamic
			? oidccCheckDiscEndpointGrantTypesSupportedDynamic(metadata, "OIDCD-3")
			: oidccCheckDiscEndpointGrantTypesSupported(metadata, "OIDCD-3"),
	);

	soft(() => checkDiscEndpointScopesSupportedSyntax(metadata, "RFC6749-3.3"));
	soft(() => checkDiscEndpointLocalesSyntax(metadata, "RFC8414-2"));
	soft(() => checkDiscEndpointLocalesCanonicalCasing(metadata, "RFC8414-2"), "warning");

	// Equivalent of VerifyOPEndpointsUseHTTPS
	// https://github.com/rohe/oidctest/blob/a306ff8ccd02da456192b595cf48ab5dcfd3d15a/src/oidctest/op/check.py#L1714
	// I'm not convinced the standards actually says every endpoint (including ones not defined by OIDC) must be https,
	// but equally it seems reasonable.
	soft(() => checkDiscEndpointAllEndpointsAreHttps(metadata));

	soft(() => ensureServerConfigurationCodeChallengeMethodsSupportedIsAnArray(metadata, "RFC8414-2", "RFC7636-4.3"));
}

/** upstream: condition/client/CheckDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256.java */
export function checkDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonArray(
		condition("CheckDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256", ...requirements),
		metadata,
		"request_object_signing_alg_values_supported",
		["RS256"],
		1,
		"Discovery endpoint request_object_signing_alg_values_supported does not include RS256.",
	);
}

/** upstream: condition/client/CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256.java */
export function checkDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonArray(
		condition("CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256", ...requirements),
		metadata,
		"userinfo_signing_alg_values_supported",
		["RS256"],
		1,
		"RS256 is not listed in userinfo_signing_alg_values_supported",
	);
}

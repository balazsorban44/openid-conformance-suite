/**
 * The OP's configuration: discovery (or a static `server` object from the test configuration) and the checks
 * upstream runs on it before a test starts.
 */
import { condition, soft, type Condition } from "../suite/conditions.ts";
import { endpointResponse, HttpError, jsonBody, request, type EndpointResponse } from "../suite/http.ts";
import type { TestConfig } from "../suite/config.ts";
import type { Op } from "./op.ts";
import type { Client } from "./registration.ts";
import { checkContentType } from "./endpoint.ts";

/** The OP's metadata (upstream env "server"): the discovery document or the configured `server` object */
export interface ServerMetadata {
	issuer?: string;
	authorization_endpoint?: string;
	token_endpoint?: string;
	userinfo_endpoint?: string;
	jwks_uri?: string;
	registration_endpoint?: string;
	token_endpoint_auth_methods_supported?: unknown;
	[key: string]: unknown;
}

/**
 * Fetches the discovery document from `server.discoveryUrl` (or `server.discoveryIssuer` +
 * /.well-known/openid-configuration).
 *
 * upstream: condition/client/GetDynamicServerConfiguration.java
 */
export async function getDynamicServerConfiguration(
	config: TestConfig,
): Promise<{ metadata: ServerMetadata; response: EndpointResponse }> {
	const c: Condition = condition("GetDynamicServerConfiguration");
	const server = (config.server ?? {}) as Record<string, unknown>;
	const staticIssuer = server["issuer"];
	if (typeof staticIssuer === "string" && staticIssuer) {
		c.failure(
			"Test set to use dynamic server configuration but test configuration contains static server configuration",
			{ issuer: staticIssuer },
		);
	}
	let discoveryUrl = typeof server["discoveryUrl"] === "string" ? server["discoveryUrl"] : "";
	if (!discoveryUrl) {
		const iss = server["discoveryIssuer"];
		if (typeof iss !== "string" || !iss) {
			c.failure("Couldn't find discoveryUrl or discoveryIssuer field for discovery purposes");
		}
		discoveryUrl = iss + "/.well-known/openid-configuration";
	}
	let res;
	try {
		res = await request(c.name, { url: discoveryUrl, method: "GET" });
	} catch (e) {
		if (e instanceof HttpError) {
			c.failureFrom("Unable to fetch server configuration from " + discoveryUrl + " - " + e.message, e);
		}
		throw e;
	}
	if (res.status >= 400) {
		// Java: RestTemplate throws RestClientResponseException on 4xx/5xx
		c.failureFrom(
			"Unable to fetch server configuration from " + discoveryUrl,
			new HttpError(res.status + " " + res.statusText + ": " + res.body),
		);
	}
	const response = endpointResponse("discovery", res);
	if (!res.body) {
		c.failure("empty server configuration");
	}
	const parsed = jsonBody(res);
	if (!parsed.ok) {
		c.failureFrom(parsed.error, new SyntaxError(parsed.error), { json: res.body });
	}
	if (typeof parsed.value !== "object" || parsed.value === null || Array.isArray(parsed.value)) {
		// Java: getAsJsonObject() throws IllegalStateException (not caught upstream)
		throw new Error("Not a JSON Object: " + res.body);
	}
	const metadata = parsed.value as ServerMetadata;
	c.success("Successfully parsed server configuration", metadata);
	return { metadata, response };
}

/** upstream: condition/client/GetStaticServerConfiguration.java */
export function getStaticServerConfiguration(config: TestConfig): ServerMetadata {
	const c: Condition = condition("GetStaticServerConfiguration");
	const server = config.server;
	if (server?.["discoveryUrl"] || server?.["discoveryIssuer"]) {
		c.failure("Test set to use static server configuration but test configuration contains discovery information", {
			discoveryUrl: server["discoveryUrl"] ?? null,
			discoveryIssuer: server["discoveryIssuer"] ?? null,
		});
	}
	if (server == null || typeof server !== "object" || Array.isArray(server)) {
		c.failure("Couldn't find server object in configuration");
	}
	c.success("Found a static server object", server);
	return server as ServerMetadata;
}

/**
 * The endpoints every OP must have, as absolute URLs.
 *
 * upstream: condition/common/CheckServerConfiguration.java (AbstractCheckServerConfiguration)
 */
export function checkServerConfiguration(metadata: ServerMetadata): void {
	const c: Condition = condition("CheckServerConfiguration");
	const required = ["authorization_endpoint", "token_endpoint", "issuer"];
	for (const key of required) {
		const value = metadata[key];
		if (typeof value !== "string" || !value) {
			c.failure("Couldn't find required component", { required: key });
		}
		// UPSTREAM: URI.create(..).toURL() additionally requires a scheme with a URL handler; new URL() accepts any
		if (!URL.canParse(value)) {
			c.failureFrom("Couldn't parse key as URL", new TypeError("Invalid URL"), { key, url: value });
		}
	}
	c.success("Found required server configuration keys", { required });
}

function tlsOf(url: string): { testHost: string; testPort: number } {
	const u = new URL(url);
	const defaults: Record<string, number> = { "http:": 80, "https:": 443, "ftp:": 21 };
	return { testHost: u.hostname, testPort: u.port !== "" ? Number(u.port) : (defaults[u.protocol] ?? -1) };
}

/**
 * The host and port of each endpoint, for TLS tests.
 *
 * upstream: condition/client/ExtractTLSTestValuesFromServerConfiguration.java
 */
export function extractTLSTestValuesFromServerConfiguration(metadata: ServerMetadata): Record<string, unknown> {
	const c: Condition = condition("ExtractTLSTestValuesFromServerConfiguration");
	try {
		const tls = (key: string) => (typeof metadata[key] === "string" && metadata[key] ? tlsOf(metadata[key]) : null);
		if (!metadata.token_endpoint) {
			c.failure("Token endpoint not found");
		}
		const values = {
			authorization_endpoint: tls("authorization_endpoint"),
			token_endpoint: tls("token_endpoint"),
			userinfo_endpoint: tls("userinfo_endpoint"),
			registration_endpoint: tls("registration_endpoint"),
		};
		c.success("Extracted TLS information from authorization server configuration", values);
		return values;
	} catch (e) {
		if (e instanceof TypeError) {
			c.failureFrom("URL not properly formed", e);
		}
		throw e;
	}
}

/** upstream: condition/client/AbstractValidateJsonArray.java */
export function validateJsonArray(
	c: Condition,
	metadata: ServerMetadata,
	key: string,
	expected: string[],
	minimumMatchesRequired: number,
	errorMessageNotEnough: string | null,
	/** upstream elementsEqual (AbstractValidateResponseTypesArray compares response types as sets) */
	elementsEqual: (expected: string, actual: string) => boolean = (a, b) => a === b,
): void {
	const actual = metadata[key];
	let error: string | null = null;
	if (actual === undefined) {
		error = key + ": not found";
	} else if (!Array.isArray(actual)) {
		error = "'" + key + "' should be an array";
	} else if (
		expected.filter((v) => actual.some((a) => elementsEqual(v, a as string))).length < minimumMatchesRequired
	) {
		error = errorMessageNotEnough;
	}
	if (error != null) {
		c.failure(
			error,
			minimumMatchesRequired === 1
				? { discovery_metadata_key: key, expected_at_least_one_of: expected, actual: actual ?? null }
				: { discovery_metadata_key: key, expected, actual: actual ?? null },
		);
	}
	c.success("Contents of '" + key + "' in discovery document matches expectations.", {
		actual: actual ?? null,
		expected,
		minimum_matches_required: minimumMatchesRequired,
	});
}

/** upstream: condition/client/EnsureServerConfigurationSupportsClientSecretBasic.java */
export function ensureServerConfigurationSupportsClientSecretBasic(metadata: ServerMetadata): void {
	const c: Condition = condition("EnsureServerConfigurationSupportsClientSecretBasic");
	if (metadata.token_endpoint_auth_methods_supported === undefined) {
		c.success(
			"server discovery document does not contain token_endpoint_auth_methods_supported, so by default client_secret_basic support is supported",
		);
		return;
	}
	validateJsonArray(
		c,
		metadata,
		"token_endpoint_auth_methods_supported",
		["client_secret_basic"],
		1,
		"server discovery document contains token_endpoint_auth_methods_supported which does not contain client_secret_basic",
	);
}

/** upstream: condition/client/EnsureServerConfigurationSupportsClientSecretPost.java */
export function ensureServerConfigurationSupportsClientSecretPost(metadata: ServerMetadata): void {
	validateJsonArray(
		condition("EnsureServerConfigurationSupportsClientSecretPost"),
		metadata,
		"token_endpoint_auth_methods_supported",
		["client_secret_post"],
		1,
		"server discovery document does not contain client_secret_post in token_endpoint_auth_methods_supported",
	);
}

/** upstream: condition/client/EnsureServerConfigurationSupportsClientAuthNone.java */
export function ensureServerConfigurationSupportsClientAuthNone(metadata: ServerMetadata): void {
	validateJsonArray(
		condition("EnsureServerConfigurationSupportsClientAuthNone"),
		metadata,
		"token_endpoint_auth_methods_supported",
		["none"],
		1,
		"server discovery document does not contain none in token_endpoint_auth_methods_supported",
	);
}

/** upstream: condition/client/EnsureServerConfigurationSupportsPrivateKeyJwt.java */
export function ensureServerConfigurationSupportsPrivateKeyJwt(metadata: ServerMetadata): void {
	const c: Condition = condition("EnsureServerConfigurationSupportsPrivateKeyJwt");
	const methods = metadata.token_endpoint_auth_methods_supported;
	if (methods == null) {
		// Null implies default (only client_secret_basic)
		c.failure("Only default auth method supported");
	}
	if (!Array.isArray(methods)) {
		// Java: getAsJsonArray() throws IllegalStateException (not caught)
		throw new Error("Not a JSON Array: " + JSON.stringify(methods));
	}
	let supported = false;
	for (const method of methods) {
		if (typeof method !== "string") {
			c.failureFrom("Invalid supported auth methods metadata", new TypeError("Expected a string"), {
				token_endpoint_auth_methods_supported: methods,
			});
		}
		if (method === "private_key_jwt") {
			c.success("Found supported private_key_jwt method", { method });
			supported = true;
		}
	}
	if (!supported) {
		c.failure("private_key_jwt is not listed as a supported client authentication method");
	}
}

/**
 * The client authentication method the variant uses must be supported (upstream AbstractOIDCCServerTest's
 * ConfigureClientFor<auth type> sequences; only checked when the OP's metadata was discovered).
 */
export function ensureServerConfigurationSupportsClientAuth(metadata: ServerMetadata, clientAuthType: string): void {
	switch (clientAuthType) {
		case "client_secret_basic":
			return ensureServerConfigurationSupportsClientSecretBasic(metadata);
		case "client_secret_post":
			return ensureServerConfigurationSupportsClientSecretPost(metadata);
		case "private_key_jwt":
			return ensureServerConfigurationSupportsPrivateKeyJwt(metadata);
		case "none":
			return ensureServerConfigurationSupportsClientAuthNone(metadata);
		default:
			throw new Error(`client_auth_type '${clientAuthType}' is not supported by src/op yet`);
	}
}

/**
 * The userinfo endpoint is the protected resource the OP tests call with the access token.
 *
 * upstream: condition/client/SetProtectedResourceUrlToUserInfoEndpoint.java
 */
export function setProtectedResourceUrlToUserInfoEndpoint(metadata: ServerMetadata): string {
	const c: Condition = condition("SetProtectedResourceUrlToUserInfoEndpoint");
	const url = metadata.userinfo_endpoint;
	if (!url) {
		c.failure(
			"userinfo_endpoint missing from server configuration. The user info is not a mandatory to implement feature in the OpenID Connect specification, but is mandatory for certification.",
		);
	}
	c.success(
		"userinfo_endpoint will be used to test access token. The user info is not a mandatory to implement feature in the OpenID Connect specification, but is mandatory for certification.",
		{ protected_resource_url: url },
	);
	return url;
}

/**
 * The scopes the test requests are listed in the discovery document's scopes_supported. Returns true when they
 * are (a failure throws).
 *
 * upstream: condition/client/OIDCCCheckScopesSupportedContainScopeTest.java
 */
export function oidccCheckScopesSupportedContainScopeTest(metadata: ServerMetadata, client: Client): true {
	const c: Condition = condition("OIDCCCheckScopesSupportedContainScopeTest");
	const scopesSupported = metadata["scopes_supported"];
	const expected = client.scope as string;
	let errorMessage: string | null = null;
	if (scopesSupported == null) {
		errorMessage = "'scopes_support' is missing from discovery document";
	} else if (!Array.isArray(scopesSupported)) {
		errorMessage = "'scopes_support' in discovery document is not a array";
	} else {
		for (const scope of expected.split(" ")) {
			if (!scopesSupported.map((s) => String(s)).includes(scope)) {
				errorMessage = "'scopes_support' in discovery document doesn't contain expected scopes";
			}
		}
	}
	if (errorMessage != null) {
		c.failure(errorMessage, { expected, actual: scopesSupported });
	}
	c.success("'scopes_supported' in discovery document contain expected scopes", {
		expected,
		actual: scopesSupported,
	});
	return true;
}

/**
 * The scope tests are skipped when the discovery document says the OP does not support the scopes they request.
 * Returns the reason to skip the test, or null.
 *
 * upstream: AbstractOIDCCReturnedClaimsServerTest.skipTestIfScopesNotSupported
 */
export function scopesNotSupportedReason(op: Pick<Op, "metadata" | "variant">, client: Client): string | null {
	if (op.variant.server_metadata !== "discovery") {
		return null;
	}
	const supported = soft(() => oidccCheckScopesSupportedContainScopeTest(op.metadata, client), "info");
	return supported
		? null
		: "scopes_supported from the discovery endpoint indicates the server doesn't support the scopes required for this test; so the test has been skipped";
}

/** upstream: condition/client/EnsureDiscoveryEndpointResponseStatusCodeIs200.java */
export function ensureDiscoveryEndpointResponseStatusCodeIs200(
	response: EndpointResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureDiscoveryEndpointResponseStatusCodeIs200", ...requirements);
	if (response.status !== 200) {
		c.failure("discovery_endpoint_response returned an unexpected status code", { http_status: response.status });
	}
	c.success("discovery_endpoint_response returned http 200 as expected", { http_status: response.status });
}

/** upstream: condition/client/CheckDiscoveryEndpointReturnedJsonContentType.java */
export function checkDiscoveryEndpointReturnedJsonContentType(
	response: EndpointResponse,
	...requirements: string[]
): void {
	checkContentType(
		"CheckDiscoveryEndpointReturnedJsonContentType",
		"discovery_endpoint_response",
		response.headers["content-type"],
		"application/json",
		...requirements,
	);
}

/**
 * The metadata value `key` is a URL with the https scheme.
 *
 * upstream: condition/client/AbstractJsonUriIsValidAndHttps.java (validate)
 */
export function validateJsonUriIsHttps(c: Condition, metadata: ServerMetadata, key: string): void {
	const value = metadata[key];
	if (value == null) {
		c.failure(key + ": URL not found");
	}
	if (typeof value !== "string") {
		c.failure(key + " is expected to be a string containing a URL", { actual: value });
	}
	let url: URL;
	try {
		url = new URL(value);
	} catch (e) {
		c.failure(key + " is not a valid URL", { actual: value, parse_error: (e as Error).message });
	}
	// Java's URL.getProtocol() has no trailing colon
	const protocol = url.protocol.replace(/:$/, "");
	if (protocol !== "https") {
		c.failure(key + " must use the https scheme", { required: "https", actual_scheme: protocol, actual: value });
	}
	c.success(key, { actual: value });
}

/**
 * Every `*_endpoint` in the metadata uses https (upstream's equivalent of the python suite's
 * VerifyOPEndpointsUseHTTPS); one entry per endpoint, stopping at the first that does not.
 *
 * upstream: condition/client/CheckDiscEndpointAllEndpointsAreHttps.java
 */
export function checkDiscEndpointAllEndpointsAreHttps(metadata: ServerMetadata, ...requirements: string[]): void {
	const c: Condition = condition("CheckDiscEndpointAllEndpointsAreHttps", ...requirements);
	for (const key of Object.keys(metadata)) {
		if (key.endsWith("_endpoint")) {
			validateJsonUriIsHttps(c, metadata, key);
		}
	}
}

/** upstream: condition/client/CheckDiscEndSessionEndpoint.java */
export function checkDiscEndSessionEndpoint(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonUriIsHttps(condition("CheckDiscEndSessionEndpoint", ...requirements), metadata, "end_session_endpoint");
}

/** upstream: condition/client/CheckDiscCheckSessionIframe.java */
export function checkDiscCheckSessionIframe(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonUriIsHttps(condition("CheckDiscCheckSessionIframe", ...requirements), metadata, "check_session_iframe");
}

/** upstream: condition/client/AbstractValidateJsonBoolean.java */
export function validateJsonBoolean(
	c: Condition,
	metadata: ServerMetadata,
	key: string,
	defaultValue: boolean,
	requiredValue: boolean,
): void {
	const value = metadata[key];
	let error: string | null = null;
	if (value === undefined) {
		if (defaultValue !== requiredValue) {
			error = `'${key}' should be '${requiredValue}', but is absent and the default value is '${defaultValue}'.`;
		}
	} else if (typeof value !== "boolean") {
		error = key + ": incorrect type, must be a boolean.";
	} else if (value !== requiredValue) {
		error = key + " must be: " + requiredValue;
	}
	if (error != null) {
		c.failure(error, { discovery_metadata_key: key, expected: requiredValue, actual: value ?? null });
	}
	c.success(key + " has correct value", { [key]: value ?? null });
}

/** upstream: condition/client/CheckDiscEndpointBackchannelLogoutSupported.java */
export function checkDiscEndpointBackchannelLogoutSupported(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonBoolean(
		condition("CheckDiscEndpointBackchannelLogoutSupported", ...requirements),
		metadata,
		"backchannel_logout_supported",
		false,
		true,
	);
}

/** upstream: condition/client/CheckDiscEndpointBackchannelLogoutSessionSupported.java */
export function checkDiscEndpointBackchannelLogoutSessionSupported(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonBoolean(
		condition("CheckDiscEndpointBackchannelLogoutSessionSupported", ...requirements),
		metadata,
		"backchannel_logout_session_supported",
		false,
		true,
	);
}

/** upstream: condition/client/CheckDiscEndpointFrontchannelLogoutSupported.java */
export function checkDiscEndpointFrontchannelLogoutSupported(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonBoolean(
		condition("CheckDiscEndpointFrontchannelLogoutSupported", ...requirements),
		metadata,
		"frontchannel_logout_supported",
		false,
		true,
	);
}

/** upstream: condition/client/CheckDiscEndpointFrontchannelLogoutSessionSupported.java */
export function checkDiscEndpointFrontchannelLogoutSessionSupported(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonBoolean(
		condition("CheckDiscEndpointFrontchannelLogoutSessionSupported", ...requirements),
		metadata,
		"frontchannel_logout_session_supported",
		false,
		true,
	);
}

/**
 * 'none' is a signing algorithm the OP supports for id_tokens (OIDCC-3.1.3.7 / OP-IDToken-none); a failure means the
 * module is skipped. Returns true when it is.
 *
 * upstream: condition/client/OIDCCCheckIdTokenSigningAlgValuesSupportedAlgNone.java
 */
export function oidccCheckIdTokenSigningAlgValuesSupportedAlgNone(
	metadata: ServerMetadata,
	...requirements: string[]
): true {
	const c: Condition = condition("OIDCCCheckIdTokenSigningAlgValuesSupportedAlgNone", ...requirements);
	const supported = metadata["id_token_signing_alg_values_supported"];
	let errorMessage: string | null = null;
	if (supported == null) {
		errorMessage = "'id_token_signing_alg_values_supported' is null";
	} else if (!Array.isArray(supported)) {
		errorMessage = "'id_token_signing_alg_values_supported' is not a json array";
	} else if (!(supported as string[]).includes("none")) {
		errorMessage = "'id_token_signing_alg_values_supported' doesn't contain 'none' algorithm'";
	}
	if (errorMessage != null) {
		c.failure(errorMessage, { id_token_signing_alg_values_supported: supported ?? null });
	}
	c.success("'id_token_signing_alg_values_supported' contain 'none' algorithm", {
		id_token_signing_alg_values_supported: supported,
	});
	return true;
}

/** upstream: condition/client/CheckDiscEndpointRequestParameterSupported.java */
export function checkDiscEndpointRequestParameterSupported(metadata: ServerMetadata, ...requirements: string[]): void {
	validateJsonBoolean(
		condition("CheckDiscEndpointRequestParameterSupported", ...requirements),
		metadata,
		"request_parameter_supported",
		false,
		true,
	);
}

/** upstream: condition/client/CheckDiscEndpointRequestUriParameterSupported.java */
export function checkDiscEndpointRequestUriParameterSupported(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	validateJsonBoolean(
		condition("CheckDiscEndpointRequestUriParameterSupported", ...requirements),
		metadata,
		"request_uri_parameter_supported",
		true,
		true,
	);
}

/**
 * Why a module that sends an unsigned (alg=none) request object is skipped: the OP lists
 * request_object_signing_alg_values_supported without "none". Null when it should run.
 *
 * upstream: AbstractOIDCCServerTest.skipTestIfNoneUnsupported
 */
export function noneRequestObjectSigningAlgUnsupported(metadata: ServerMetadata): string | null {
	const supported = metadata["request_object_signing_alg_values_supported"];
	if (Array.isArray(supported) && !supported.includes("none")) {
		return "'none' is not listed in request_object_signing_alg_values_supported - assuming it is not supported.";
	}
	return null;
}

/** upstream: condition/client/EnsureServerConfigurationSupportsRefreshToken.java */
export function ensureServerConfigurationSupportsRefreshToken(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureServerConfigurationSupportsRefreshToken", ...requirements);
	const supportedGrantTypes = metadata["grant_types_supported"];
	if (supportedGrantTypes == null) {
		// Null implies default ["authorization_code", "implicit"]
		c.failure(
			"The server issued a refresh token but does not claim to support this grant type (grant_types_supported in not present in the discovery document)",
		);
	}
	if (!Array.isArray(supportedGrantTypes)) {
		c.failure("supported_grant_types is present in the discovery document but is not an array");
	}
	if (supportedGrantTypes.includes("refresh_token")) {
		c.success("The server configuration indicates support for refresh tokens", {
			supported_grant_types: supportedGrantTypes,
		});
		return;
	}
	c.failure("The server issued a refresh token but does not claim to support this grant type", {
		supported_grant_types: supportedGrantTypes,
	});
}

/** upstream: condition/client/EnsureServerConfigurationDoesNotSupportRefreshToken.java */
export function ensureServerConfigurationDoesNotSupportRefreshToken(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureServerConfigurationDoesNotSupportRefreshToken", ...requirements);
	const supportedGrantTypes = metadata["grant_types_supported"];
	if (supportedGrantTypes == null) {
		// Null implies default ["authorization_code", "implicit"]
		c.success(
			"The server did not issue a refresh token and does not claim to support this grant type (grant_types_supported in not present in the discovery document)",
		);
		return;
	}
	if (!Array.isArray(supportedGrantTypes)) {
		c.failure("supported_grant_types is present in the discovery document but is not an array");
	}
	if (supportedGrantTypes.includes("refresh_token")) {
		c.failure(
			"The server supports refresh tokens, but did not issue one. This is acceptable if the server has a policy of issuing refresh tokens to some clients, but not to openid clients.",
			{ supported_grant_types: supportedGrantTypes },
		);
	}
	c.success("The server did not issue a refresh token, and does not claim to support this grant type", {
		supported_grant_types: supportedGrantTypes,
	});
}

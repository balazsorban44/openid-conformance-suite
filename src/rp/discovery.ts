/**
 * The emulated OP's metadata (upstream env "server"), served at `<issuer>.well-known/openid-configuration`: generated
 * per test (OIDCCGenerateServerConfiguration and its variants), adjusted to the client authentication the variant
 * selects, and checked for the metadata OpenID Connect Discovery requires.
 */
import type { ServerMetadata } from "../op/discovery.ts";
import { condition, type Condition } from "../suite/conditions.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import {
	ENC_FAMILY_AES_CBC_HMAC_SHA,
	ENC_FAMILY_AES_GCM,
	JWE_FAMILY_ASYMMETRIC,
	JWE_FAMILY_SYMMETRIC,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_SIGNATURE,
} from "../suite/jose-algorithms.ts";
import { SUPPORTED_CLAIMS } from "./userinfo.ts";

export type { ServerMetadata } from "../op/discovery.ts";

/** The parts of OIDCCGenerateServerConfiguration its subclasses override */
interface ServerConfigurationOverrides {
	idTokenSigningAlgValuesSupported?: string[];
	grantTypes?: string[];
	/** addAdditionalConfiguration: called last */
	additional?: (server: ServerMetadata, baseUrl: string) => void;
	/** The requirements the call site passes (upstream callAndStopOnFailure(..., "OIDCSM-3.3", ...)) */
	requirements?: string[];
}

/**
 * The document of OIDCCGenerateServerConfiguration on the base of upstream: condition/as/GenerateServerConfiguration.java
 * (createBaseConfiguration). `name` is the condition the entry is logged under (the subclasses of
 * OIDCCGenerateServerConfiguration only change parts of the document).
 */
function generateServerConfiguration(name: string, baseUrl: string, o: ServerConfigurationOverrides): ServerMetadata {
	const c: Condition = condition(name, ...(o.requirements ?? []));
	const base = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
	const asymmetricAndSymmetric = [...JWE_FAMILY_ASYMMETRIC, ...JWE_FAMILY_SYMMETRIC];
	const encValues = [...ENC_FAMILY_AES_CBC_HMAC_SHA, ...ENC_FAMILY_AES_GCM];
	const authMethods = ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"];
	const server: ServerMetadata = {
		issuer: base,
		authorization_endpoint: base + "authorize",
		token_endpoint: base + "token",
		jwks_uri: base + "jwks",
		userinfo_endpoint: base + "userinfo",
		registration_endpoint: base + "register",
		scopes_supported: ["openid", "phone", "profile", "email", "address", "offline_access"],
		// response types are intentionally in unusual order
		response_types_supported: [
			"code",
			"id_token code",
			"token code id_token",
			"id_token",
			"token id_token",
			"token code",
			"token",
		],
		response_modes_supported: ["query", "fragment", "form_post"],
		token_endpoint_auth_methods_supported: authMethods,
		token_endpoint_auth_signing_alg_values_supported: authMethods.flatMap((m) =>
			m === "private_key_jwt" ? [...JWS_FAMILY_SIGNATURE] : m === "client_secret_jwt" ? [...JWS_FAMILY_HMAC_SHA] : [],
		),
		// the python suite also returned urn:ietf:params:oauth:grant-type:jwt-bearer and refresh_token; refresh_token
		// is only added for the refresh token tests
		grant_types_supported: o.grantTypes ?? ["authorization_code", "implicit"],
		claims_parameter_supported: true,
		acr_values_supported: ["PASSWORD"],
		subject_types_supported: ["public", "pairwise"],
		claim_types_supported: ["normal", "aggregated", "distributed"],
		claims_supported: [...SUPPORTED_CLAIMS],
		id_token_signing_alg_values_supported: o.idTokenSigningAlgValuesSupported ?? ["none", ...JWS_FAMILY_SIGNATURE],
		id_token_encryption_alg_values_supported: asymmetricAndSymmetric,
		id_token_encryption_enc_values_supported: encValues,
		request_object_signing_alg_values_supported: ["none", ...JWS_FAMILY_SIGNATURE],
		request_object_encryption_alg_values_supported: asymmetricAndSymmetric,
		request_object_encryption_enc_values_supported: encValues,
		userinfo_signing_alg_values_supported: [...JWS_FAMILY_SIGNATURE],
		userinfo_encryption_alg_values_supported: asymmetricAndSymmetric,
		userinfo_encryption_enc_values_supported: encValues,
	};
	o.additional?.(server, base);
	c.success("Generated default server configuration", { server_configuration: server });
	return server;
}

/** upstream: condition/as/OIDCCGenerateServerConfiguration.java */
export function oidccGenerateServerConfiguration(baseUrl: string): ServerMetadata {
	return generateServerConfiguration("OIDCCGenerateServerConfiguration", baseUrl, {});
}

/** upstream: condition/as/OIDCCGenerateServerConfigurationWithRefreshTokenGrantType.java */
export function oidccGenerateServerConfigurationWithRefreshTokenGrantType(baseUrl: string): ServerMetadata {
	return generateServerConfiguration("OIDCCGenerateServerConfigurationWithRefreshTokenGrantType", baseUrl, {
		grantTypes: ["authorization_code", "implicit", "refresh_token"],
	});
}

/** upstream: condition/as/OIDCCGenerateServerConfigurationIdTokenSigningAlgRS256Only.java */
export function oidccGenerateServerConfigurationIdTokenSigningAlgRS256Only(baseUrl: string): ServerMetadata {
	return generateServerConfiguration("OIDCCGenerateServerConfigurationIdTokenSigningAlgRS256Only", baseUrl, {
		idTokenSigningAlgValuesSupported: ["RS256"],
	});
}

/** The condition that restricts token_endpoint_auth_methods_supported to the variant's method */
const TOKEN_ENDPOINT_AUTH_METHOD_ONLY: Record<string, string> = {
	client_secret_basic: "SetTokenEndpointAuthMethodsSupportedToClientSecretBasicOnly",
	client_secret_post: "SetTokenEndpointAuthMethodsSupportedToClientSecretPostOnly",
	client_secret_jwt: "SetTokenEndpointAuthMethodsSupportedToClientSecretJWTOnly",
	private_key_jwt: "SetTokenEndpointAuthMethodsSupportedToPrivateKeyJWTOnly",
	tls_client_auth: "SetTokenEndpointAuthMethodsSupportedToTlsClientAuthOnly",
	self_signed_tls_client_auth: "SetTokenEndpointAuthMethodsSupportedToSelfSignedTlsClientAuthOnly",
};

/**
 * Restricts token_endpoint_auth_methods_supported to the variant's client authentication (nothing for `none`).
 *
 * upstream: condition/as/SetTokenEndpointAuthMethodsSupportedToClientSecretBasicOnly.java,
 * SetTokenEndpointAuthMethodsSupportedToClientSecretPostOnly.java, SetTokenEndpointAuthMethodsSupportedToClientSecretJWTOnly.java,
 * SetTokenEndpointAuthMethodsSupportedToPrivateKeyJWTOnly.java, SetTokenEndpointAuthMethodsSupportedToTlsClientAuthOnly.java,
 * SetTokenEndpointAuthMethodsSupportedToSelfSignedTlsClientAuthOnly.java (AbstractOIDCCClientTest.setup<auth type>)
 */
export function setTokenEndpointAuthMethodsSupportedOnly(server: ServerMetadata, clientAuthType: string): void {
	const name = TOKEN_ENDPOINT_AUTH_METHOD_ONLY[clientAuthType];
	if (name == null) {
		return;
	}
	server.token_endpoint_auth_methods_supported = [clientAuthType];
	condition(name).log(
		`Changed token_endpoint_auth_methods_supported to ${clientAuthType} only in server configuration`,
		{ server_configuration: server },
	);
}

/** upstream: condition/as/EnsureServerConfigurationHasRequiredOidcMetadata.java */
export function ensureServerConfigurationHasRequiredOidcMetadata(
	server: ServerMetadata,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureServerConfigurationHasRequiredOidcMetadata", ...requirements);
	const required = [
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	];
	const missing = required.filter((field) => server[field] == null);
	if (missing.length > 0) {
		c.failure(
			"The discovery document this test publishes is missing metadata OpenID Connect Discovery requires. " +
				"This is a bug in the conformance suite, please report it.",
			{ missing, server },
		);
	}
	c.success("The discovery document contains all metadata required by OpenID Connect Discovery", { server });
}

/** The discovery response (upstream handleDiscoveryEndpointRequest: an empty "Discovery endpoint" block) */
export function discoveryResponse(server: ServerMetadata): Response {
	return Response.json(server);
}

/**
 * A random suffix on the issuer (the discovery document is then served below it), so the RP has to use WebFinger to
 * find it. upstream: condition/as/AddRandomSuffixToIssuerInServerConfiguration.java
 */
export function addRandomSuffixToIssuerInServerConfiguration(server: ServerMetadata): void {
	const newIssuer = String(server.issuer) + randomAlphanumeric(10);
	server.issuer = newIssuer;
	condition("AddRandomSuffixToIssuerInServerConfiguration").log(
		"Added random suffix to issuer value in server configuration",
		{ issuer: newIssuer },
	);
}

/** upstream: condition/as/ChangeIssuerInServerConfigurationToBeInvalid.java */
export function changeIssuerInServerConfigurationToBeInvalid(server: ServerMetadata): void {
	const newIssuer = String(server.issuer) + "INVALID";
	server.issuer = newIssuer;
	condition("ChangeIssuerInServerConfigurationToBeInvalid").log("Added invalid issuer to server configuration", {
		issuer: newIssuer,
	});
}

/** `suffix`: upstream "random_jwks_uri_suffix". upstream: condition/as/AddRandomJwksUriToServerConfiguration.java */
export function addRandomJwksUriToServerConfiguration(server: ServerMetadata, suffix: string): void {
	const newJwksUri = String(server.jwks_uri) + suffix;
	server.jwks_uri = newJwksUri;
	condition("AddRandomJwksUriToServerConfiguration").log("Added random jwks_uri to server configuration", {
		jwks_uri: newJwksUri,
	});
}

/** upstream: condition/as/OIDCCGenerateServerConfigurationWithSessionManagement.java */
export function oidccGenerateServerConfigurationWithSessionManagement(
	baseUrl: string,
	...requirements: string[]
): ServerMetadata {
	return generateServerConfiguration("OIDCCGenerateServerConfigurationWithSessionManagement", baseUrl, {
		requirements,
		additional: (server, base) => {
			server["check_session_iframe"] = base + "check_session_iframe";
			server["end_session_endpoint"] = base + "end_session_endpoint";
			server["frontchannel_logout_supported"] = true;
			server["frontchannel_logout_session_supported"] = true;
			server["backchannel_logout_supported"] = true;
			server["backchannel_logout_session_supported"] = true;
		},
	});
}

// ---------------------------------------------------------------------------------------------------------------
// the FAPI 2 authorization server's configuration (upstream AbstractFAPI2SPFinalClientTest.configure)

/**
 * The base url an mTLS client would use (upstream base_mtls_url: the suite's /test-mtls/ listener). The port has
 * no mTLS listener: the aliases are published because RFC 8705 section 5 requires clients to support them, and a
 * private_key_jwt + DPoP client never calls them.
 */
export function mtlsBaseUrl(baseUrl: string): string {
	return baseUrl.replace("/test/", "/test-mtls/");
}

/**
 * The base document of a FAPI 2 authorization server: the issuer, the endpoints and their mtls_endpoint_aliases.
 * `name`: the condition the entry is logged under; `discoveryUrl`: where the document is served (upstream
 * getDiscoveryUrl). Returns the document and the discovery url (upstream "discoveryUrl").
 */
function generateServerConfigurationMTLS(
	name: string,
	baseUrl: string,
	baseMtlsUrl: string,
	discoveryUrl: (c: Condition, base: string) => string,
): { server: ServerMetadata; discoveryUrl: string } {
	const c: Condition = condition(name);
	if (baseUrl === "") {
		c.failure("Base URL is empty");
	}
	if (baseMtlsUrl === "") {
		c.failure("Base MTLS URL is empty");
	}
	// set off the URLs below with a slash, if needed
	const base = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
	const mtls = baseMtlsUrl.endsWith("/") ? baseMtlsUrl : baseMtlsUrl + "/";
	const server: ServerMetadata = {
		issuer: base,
		authorization_endpoint: base + "authorize",
		token_endpoint: base + "token",
		registration_endpoint: base + "register",
		userinfo_endpoint: base + "userinfo",
		mtls_endpoint_aliases: {
			token_endpoint: mtls + "token",
			registration_endpoint: mtls + "register",
			userinfo_endpoint: mtls + "userinfo",
		},
	};
	const discoverUrl = discoveryUrl(c, base);
	c.success("Created server configuration", { server, issuer: base, discoveryUrl: discoverUrl });
	return { server, discoveryUrl: discoverUrl };
}

/** upstream: condition/as/GenerateServerConfigurationMTLS.java */
export function generateServerConfigurationMTLSOpenId(
	baseUrl: string,
	baseMtlsUrl: string,
): { server: ServerMetadata; discoveryUrl: string } {
	return generateServerConfigurationMTLS(
		"GenerateServerConfigurationMTLS",
		baseUrl,
		baseMtlsUrl,
		(_c, base) => base + ".well-known/openid-configuration",
	);
}

/**
 * The OAuth 2.0 (RFC 8414) discovery url: `<origin>/.well-known/oauth-authorization-server<path>`.
 *
 * upstream: condition/as/GenerateOauthServerConfigurationMTLS.java
 */
export function generateOauthServerConfigurationMTLS(
	baseUrl: string,
	baseMtlsUrl: string,
): { server: ServerMetadata; discoveryUrl: string } {
	return generateServerConfigurationMTLS("GenerateOauthServerConfigurationMTLS", baseUrl, baseMtlsUrl, (c, base) => {
		if (!URL.canParse(base)) {
			c.failureFrom("Invalid URL", new Error("no protocol: " + base), { baseUrl: base });
		}
		const url = new URL(base);
		if (url.pathname) {
			const foundIndex = base.indexOf(url.pathname);
			if (foundIndex !== -1) {
				return base.substring(0, foundIndex) + "/.well-known/oauth-authorization-server" + url.pathname;
			}
		}
		// UPSTREAM: the fallback url has "./well-known" (sic)
		return base + "./well-known/oauth-authorization-server";
	});
}

/** upstream: condition/as/AddJwksUriToServerConfiguration.java */
export function addJwksUriToServerConfiguration(server: ServerMetadata, baseUrl: string): void {
	const c: Condition = condition("AddJwksUriToServerConfiguration");
	if (baseUrl === "") {
		c.failure("Base URL is empty");
	}
	const uri = (baseUrl.endsWith("/") ? baseUrl : baseUrl + "/") + "jwks";
	server.jwks_uri = uri;
	c.log("Added jwks_uri to server configuration", { jwks_uri: uri });
}

/** upstream: condition/as/AddResponseTypeCodeToServerConfiguration.java */
export function addResponseTypeCodeToServerConfiguration(server: ServerMetadata, ...requirements: string[]): void {
	const data = ["code"];
	server.response_types_supported = data;
	condition("AddResponseTypeCodeToServerConfiguration", ...requirements).success(
		"Added code as response type supported",
		{ response_types_supported: data },
	);
}

/** upstream: condition/as/AddIssSupportedToServerConfiguration.java */
export function addIssSupportedToServerConfiguration(server: ServerMetadata, ...requirements: string[]): void {
	server["authorization_response_iss_parameter_supported"] = true;
	condition("AddIssSupportedToServerConfiguration", ...requirements).success(
		"Added 'authorization_response_iss_parameter_supported' as 'true' to server metadata",
	);
}

/** upstream: condition/as/AddCodeChallengeMethodToServerConfiguration.java */
export function addCodeChallengeMethodToServerConfiguration(server: ServerMetadata, ...requirements: string[]): void {
	const data = ["S256"];
	server["code_challenge_methods_supported"] = data;
	condition("AddCodeChallengeMethodToServerConfiguration", ...requirements).success(
		"Added S256 as supported code challenge method",
		{ code_challenge_methods_supported: data },
	);
}

/** upstream: condition/as/AddScopesSupportedOpenIdToServerConfiguration.java */
export function addScopesSupportedOpenIdToServerConfiguration(server: ServerMetadata): void {
	server.scopes_supported = ["openid"];
	condition("AddScopesSupportedOpenIdToServerConfiguration").success(
		"Added 'scopes_supported' as 'openid' to server metadata",
	);
}

/** upstream: condition/as/AddSubjectTypesSupportedToServerConfiguration.java */
export function addSubjectTypesSupportedToServerConfiguration(server: ServerMetadata, ...requirements: string[]): void {
	server.subject_types_supported = ["public", "pairwise"];
	condition("AddSubjectTypesSupportedToServerConfiguration", ...requirements).log(
		"Added public/pairwise to subject_types_supported in server metadata",
		{ server },
	);
}

/** upstream: condition/as/AddIdTokenSigningAlgsToServerConfiguration.java */
export function addIdTokenSigningAlgsToServerConfiguration(server: ServerMetadata, signingAlg: string): void {
	const data = [signingAlg];
	server.id_token_signing_alg_values_supported = data;
	condition("AddIdTokenSigningAlgsToServerConfiguration").success(
		"Added 'id_token_signing_alg_values_supported' to server metadata as 'alg' from server jwks",
		{ value: data },
	);
}

/** The algorithms FAPI 2.0 allows (upstream FAPI2CheckDiscEndpointIdTokenSigningAlgValuesSupported.FAPI2_ALLOWED_ALGS) */
export const FAPI2_ALLOWED_ALGS: readonly string[] = ["PS256", "ES256", "EdDSA", "Ed25519"];

/** upstream: condition/as/FAPI2AddRequestObjectSigningAlgValuesSupportedToServerConfiguration.java */
export function fapi2AddRequestObjectSigningAlgValuesSupportedToServerConfiguration(server: ServerMetadata): void {
	const algs = [...FAPI2_ALLOWED_ALGS];
	server.request_object_signing_alg_values_supported = algs;
	condition("FAPI2AddRequestObjectSigningAlgValuesSupportedToServerConfiguration").success(
		"Added 'request_object_signing_alg_values_supported' to server metadata",
		{ value: algs },
	);
}

/** upstream: condition/as/AddDpopSigningAlgValuesSupportedToServerConfiguration.java */
export function addDpopSigningAlgValuesSupportedToServerConfiguration(
	server: ServerMetadata,
	...requirements: string[]
): void {
	const data = [...FAPI2_ALLOWED_ALGS];
	server["dpop_signing_alg_values_supported"] = data;
	condition("AddDpopSigningAlgValuesSupportedToServerConfiguration", ...requirements).success(
		"Set dpop_signing_alg_values_supported",
		{ values: data },
	);
}

/** upstream: condition/as/FAPI2AddTokenEndpointAuthSigningAlgValuesSupportedToServer.java */
export function fapi2AddTokenEndpointAuthSigningAlgValuesSupportedToServer(server: ServerMetadata): void {
	const algs = [...FAPI2_ALLOWED_ALGS];
	server.token_endpoint_auth_signing_alg_values_supported = algs;
	condition("FAPI2AddTokenEndpointAuthSigningAlgValuesSupportedToServer").success(
		"Set token_endpoint_auth_signing_alg_values_supported",
		{ values: algs },
	);
}

/**
 * The scopes the configured clients request (`client.scope`, `client2.scope`) are added to scopes_supported, so the
 * metadata matches what the client under test asks for.
 *
 * upstream: condition/as/AddConfiguredScopesToServerConfiguration.java
 */
export function addConfiguredScopesToServerConfiguration(
	server: ServerMetadata,
	config: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("AddConfiguredScopesToServerConfiguration", ...requirements);
	const scopes = new Set<string>();
	const existing = server.scopes_supported as unknown;
	if (existing != null) {
		if (!Array.isArray(existing)) {
			c.failure("'scopes_supported' in the server configuration is not an array", { scopes_supported: existing });
		}
		for (const s of existing) {
			scopes.add(String(s));
		}
	}
	for (const clientKey of ["client", "client2"]) {
		const client = config[clientKey];
		const scopeElement =
			client != null && typeof client === "object" && !Array.isArray(client)
				? (client as Record<string, unknown>)["scope"]
				: undefined;
		if (scopeElement == null) {
			continue;
		}
		if (typeof scopeElement !== "string") {
			c.failure("The 'scope' field in the client section of the test configuration is not a string", {
				client: clientKey,
				scope: scopeElement,
			});
		}
		for (const scope of scopeElement.split(/\s+/)) {
			if (scope !== "") {
				scopes.add(scope);
			}
		}
	}
	if (scopes.size === 0) {
		// no scopes are configured and none were published; publishing an empty array would be worse than omitting
		// the (only RECOMMENDED) field entirely
		c.success("No scopes are configured, leaving 'scopes_supported' as it is", { server });
		return;
	}
	const scopesSupported = [...scopes];
	server.scopes_supported = scopesSupported;
	c.success("Set 'scopes_supported' in the server metadata to include the configured scopes", {
		scopes_supported: scopesSupported,
	});
}

/** upstream: condition/as/RemoveMtlsEndpointAliasesFromServerConfiguration.java */
export function removeMtlsEndpointAliasesFromServerConfiguration(
	server: ServerMetadata,
	...requirements: string[]
): void {
	delete server["mtls_endpoint_aliases"];
	condition("RemoveMtlsEndpointAliasesFromServerConfiguration", ...requirements).log(
		"Removed mtls_endpoint_aliases from server configuration",
	);
}

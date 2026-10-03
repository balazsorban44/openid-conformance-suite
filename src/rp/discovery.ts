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

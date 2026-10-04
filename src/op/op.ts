/**
 * What an OP test works with (the `op` fixture in tests/fixtures.ts provides it): the OP under test as the suite
 * discovered it, and the suite's own side of the conversation (its server, the scripted browser, the log).
 */
import type { Browser } from "../suite/browser.ts";
import type { TestConfig } from "../suite/config.ts";
import type { Jwks } from "../suite/jose.ts";
import type { EventLog } from "../suite/log.ts";
import type { TestServer } from "../suite/server.ts";
import type { ServerMetadata } from "./discovery.ts";

/** The variant parameters of the OIDCC OP test modules (upstream variant/*.java values) */
export interface OpVariant {
	server_metadata: "discovery" | "static";
	client_registration: "dynamic_client" | "static_client";
	client_auth_type:
		| "none"
		| "client_secret_basic"
		| "client_secret_post"
		| "client_secret_jwt"
		| "private_key_jwt"
		| "mtls";
	response_type: "code" | "id_token" | "id_token token" | "code id_token" | "code token" | "code id_token token";
	response_mode: "default" | "form_post";
	[parameter: string]: string;
}

/**
 * The variant parameters of the FAPI 2.0 OP test modules (upstream fapi2spfinal/AbstractFAPI2SPFinalServerTestModule
 * @VariantParameters: variant/ClientAuthType, FAPI2AuthRequestMethod, FAPIOpenIDConnect, FAPI2SenderConstrainMethod,
 * FAPI2FinalOPProfile, FAPIResponseMode, AuthorizationRequestType, GrantManagement). The port covers
 * client_auth_type=private_key_jwt, sender_constrain=dpop, fapi_profile=plain_fapi, authorization_request_type=simple
 * and grant_management=disabled; mTLS (client authentication and sender constraining), client_attestation, RAR, grant
 * management and the ecosystem profiles are not ported.
 */
export interface Fapi2Variant {
	client_auth_type: "private_key_jwt" | "mtls" | "client_attestation";
	fapi_request_method: "unsigned" | "signed_non_repudiation";
	openid: "plain_oauth" | "openid_connect";
	sender_constrain: "mtls" | "dpop";
	fapi_profile:
		| "plain_fapi"
		| "consumerdataright_au"
		| "openbanking_brazil"
		| "connectid_au"
		| "cbuae"
		| "openbanking_chile"
		| "ksa"
		| "fapi_client_credentials_grant"
		| "vci"
		| "vci_haip";
	fapi_response_mode: "plain_response" | "jarm";
	authorization_request_type: "simple" | "rar";
	grant_management: "disabled" | "enabled";
	[parameter: string]: string;
}

/**
 * The OP without its keys (the `registrationOp` fixture): the redirect_uri, the metadata and CheckServerConfiguration,
 * as upstream's AbstractOIDCCDynamicRegistrationTest.configure sets it up for the modules that only register clients.
 * The `op` fixture builds on it (ExtractTLSTestValuesFromServerConfiguration, the OP's keys).
 */
export type RegistrationOp = Omit<Op, "jwks">;

/**
 * The OP under test of a FAPI 2.0 module (the `fapi` fixture): the same as {@link Op} with the FAPI 2 variant; its
 * keys are only fetched with OpenID Connect or JARM (upstream fetches them when `isOpenId || jarm`)
 */
export type Fapi2Op = Omit<Op<Fapi2Variant>, "jwks"> & { jwks: Jwks | null };

export interface Op<V extends Record<string, string> = OpVariant> {
	/** The test module name (upstream testName), e.g. "oidcc-server" */
	testName: string;
	testId: string;
	/** The test configuration for this module (`override` applied) */
	config: TestConfig;
	variant: V;
	/** The OP's metadata (upstream env "server") */
	metadata: ServerMetadata;
	/** The OP's JWK set (upstream env "server_jwks") */
	jwks: Jwks;
	/** The suite's URL for this test (upstream base_url) */
	baseUrl: string;
	/** The suite's redirect_uri (upstream CreateRedirectUri) */
	redirectUri: string;
	server: TestServer;
	browser: Browser;
	log: EventLog;
}

/**
 * The emulated FAPI 2.0 authorization server an RP test runs against (upstream
 * fapi2spfinal/AbstractFAPI2SPFinalClientTest.java with the plain_fapi FAPI2ClientProfileBehavior): its configuration
 * (the discovery document with mtls_endpoint_aliases, PAR, DPoP, JARM; the keys with decoys and an alternate RSA
 * key; the static client and its public keys), the endpoints on the test's server (discovery, jwks, PAR,
 * authorization, token, userinfo, the accounts resource) with the checks upstream runs on every request the RP
 * sends (private_key_jwt client assertions, DPoP proofs and nonces, PKCE, the signed request object), and the
 * events a test follows.
 *
 *   const as = await rp.startFapi2({ addCustomValuesToIdToken: (claims) => idToken.addInvalidIssValueToIdToken(claims, "OIDCC-3.1.3.7-2") });
 *   const client = rp.driveClient();
 *   await expectWithDpopNonce(as, "par");        // the PAR request (after the use_dpop_nonce challenge)
 *   await as.expect("authorization");
 *   await expectWithDpopNonce(as, "token");
 *   await as.waitFor("accounts", rp.waitTimeoutSeconds);   // the RP must stop
 *
 * Ported variants: client_auth_type=private_key_jwt, sender_constrain=dpop, fapi_profile=plain_fapi,
 * fapi_client_type oidc / plain_oauth, fapi_request_method unsigned / signed_non_repudiation, fapi_response_mode
 * plain_response / jarm, authorization_request_type=simple, grant_management=disabled. mTLS (client authentication,
 * sender constraining, the /test-mtls/ listener), client attestation, RAR, grant management and the ecosystem
 * profiles are not.
 */
import { randomUUID } from "node:crypto";
import { checkServerConfiguration } from "../op/discovery.ts";
import {
	checkDistinctKeyIdValueInClientJWKs,
	fapi2FinalEnsureMinimumClientKeyLength,
	fapi2FinalEnsureMinimumServerKeyLength,
	validateJwks,
} from "../op/jwks.ts";
import { ensureIncomingTls13 } from "../op/logout.ts";
import {
	extractJWKsFromStaticClientConfiguration,
	getStaticClientConfiguration,
	type ClientKeys,
} from "../op/registration.ts";
import { block, condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import type { TestConfig } from "../suite/config.ts";
import type { Jwks, ParsedJwt } from "../suite/jose.ts";
import type { IncomingRequest, TestServer } from "../suite/server.ts";
import * as authz from "./authorization.ts";
import type { AuthorizationParams } from "./authorization.ts";
import * as clientAssertion from "./client-assertion.ts";
import * as discovery from "./discovery.ts";
import type { ServerMetadata } from "./discovery.ts";
import * as dpop from "./dpop.ts";
import type { DpopAccessToken, DpopErrorResponse, DpopNonces, DpopProof, JtiCache } from "./dpop.ts";
import * as idToken from "./id-token.ts";
import type { IdTokenClaims } from "./id-token.ts";
import * as jarm from "./jarm.ts";
import type { JarmClaims } from "./jarm.ts";
import * as jwks from "./jwks.ts";
import type { ServerKeys } from "./jwks.ts";
import { createRequestDispatcher, failTest, type RequestDispatcher } from "./op.ts";
import * as par from "./par.ts";
import type { ParParams } from "./par.ts";
import type { RpClient } from "./registration.ts";
import * as requestObject from "./request-object.ts";
import * as token from "./token.ts";
import type { CodeChallenge } from "./token.ts";
import {
	clearAccessTokenFromRequest,
	filterUserInfoForScopes,
	userInfoClaimsValues,
	type UserInfo,
} from "./userinfo.ts";

/** The variant parameters of the FAPI 2 client test modules (upstream variant/*.java values) */
export interface Fapi2RpVariant {
	client_auth_type: "private_key_jwt" | "mtls" | "client_attestation";
	fapi_profile: string;
	fapi_response_mode: "plain_response" | "jarm";
	fapi_client_type: "oidc" | "plain_oauth";
	fapi_request_method: "unsigned" | "signed_non_repudiation";
	sender_constrain: "dpop" | "mtls";
	authorization_request_type: "simple" | "rar";
	grant_management: "disabled" | "enabled";
	[parameter: string]: string;
}

/** upstream AbstractFAPI2SPFinalClientTest.ACCOUNTS_PATH */
export const ACCOUNTS_PATH = "open-banking/v1.1/accounts";

export type Fapi2Endpoint = "discovery" | "jwks" | "par" | "authorization" | "token" | "userinfo" | "accounts";

/** An answered request: its response, and the nonce the use_dpop_nonce challenge supplied when the request got one */
interface AnsweredRequest {
	request: IncomingRequest;
	status: number;
	/** upstream "<endpoint>_endpoint_dpop_nonce_error": the request was answered with a use_dpop_nonce error */
	dpopNonceError: string | null;
}

/** What expect()/waitFor() resolve with: the request and what the server answered */
export interface Fapi2AsEvents {
	discovery: { request: IncomingRequest };
	jwks: { request: IncomingRequest };
	par: AnsweredRequest & { response: Record<string, unknown> };
	authorization: {
		request: IncomingRequest;
		/** upstream "authorization_endpoint_response_params" (without redirect_uri with JARM) */
		response: Record<string, string>;
		/** upstream "authorization_endpoint_response_redirect" */
		redirect: string;
		/** upstream "jarm_response" (fapi_response_mode=jarm) */
		jarmResponse: string | null;
	};
	token: AnsweredRequest & { response: Record<string, unknown> };
	userinfo: AnsweredRequest & { response: UserInfo | null };
	accounts: AnsweredRequest & { response: Record<string, unknown> | null };
}

/**
 * How a module's authorization server differs from the default one: upstream's overridable methods as options,
 * named after them; the callbacks call the upstream condition functions themselves (with upstream's requirements).
 */
export interface Fapi2AsOptions {
	/** Runs at the end of configure, after the DPoP nonces are created (upstream onConfigurationCompleted) */
	onConfigurationCompleted?: (as: Fapi2As) => void;
	/** Changes to the server configuration before it is checked (upstream adjustServerConfigurationForMtlsEndpointAliasesVariant) */
	adjustServerConfigurationForMtlsEndpointAliasesVariant?: (server: ServerMetadata, as: Fapi2As) => void;
	/** Whether the authorization server endpoints require a DPoP nonce (upstream requireAuthorizationServerEndpointDpopNonce); default true */
	requireAuthorizationServerEndpointDpopNonce?: boolean;
	/** Whether the resource server endpoints require a DPoP nonce (upstream requireResourceServerEndpointDpopNonce); default true */
	requireResourceServerEndpointDpopNonce?: boolean;
	/** Changes to the id_token claims before they are signed (upstream addCustomValuesToIdToken) */
	addCustomValuesToIdToken?: (claims: IdTokenClaims, as: Fapi2As) => void;
	/** Replaces the signed id_token (upstream addCustomSignatureOfIdToken) */
	addCustomSignatureOfIdToken?: (idToken: string, claims: IdTokenClaims, as: Fapi2As) => string | Promise<string>;
	/** Runs once an id_token was issued (upstream issueIdToken overridden: AbstractFAPI2SPFinalClientExpectNothingAfterIdTokenIssued) */
	afterIdTokenIssued?: (as: Fapi2As) => void;
	/** Runs after the access token was issued (upstream issueAccessToken overridden) */
	afterAccessTokenIssued?: (as: Fapi2As) => void;
	/** Checks before the authorization response is created (upstream createAuthorizationEndpointResponse overridden: the happy path's nonce / state checks) */
	beforeAuthorizationResponse?: (effective: AuthorizationParams, as: Fapi2As) => void;
	/** Changes to the authorization response parameters (upstream addCustomValuesToAuthorizationResponse) */
	addCustomValuesToAuthorizationResponse?: (params: Record<string, string>, as: Fapi2As) => void;
	/** Runs once the authorization response was created (upstream createAuthorizationEndpointResponse overridden: AbstractFAPI2SPFinalClientExpectNothingAfterAuthorizationResponse) */
	afterAuthorizationResponse?: (as: Fapi2As) => void;
	/** Changes to the JARM response claims (upstream addCustomValuesToJarmResponse) */
	addCustomValuesToJarmResponse?: (claims: JarmClaims, as: Fapi2As) => void;
	/** Signs (and encrypts) the JARM response claims instead of SignJARMResponse + encryptJARMResponse (upstream createJARMResponse overridden) */
	createJARMResponse?: (claims: JarmClaims, as: Fapi2As) => Promise<string>;
	/** Ends the test as skipped when the request lacks what the module tests (upstream endTestIfRequiredParametersAreMissing) */
	endTestIfRequiredParametersAreMissing?: (effective: AuthorizationParams, as: Fapi2As) => void;
	/** A custom error response of the PAR endpoint, after the checks (upstream createPAREndpointCustomErrorResponse) */
	createPAREndpointCustomErrorResponse?: (as: Fapi2As) => Response | null;
	/** Changes to the PAR response (upstream addCustomValuesToParResponse) */
	addCustomValuesToParResponse?: (response: Record<string, unknown>, as: Fapi2As) => void;
	/** Runs once the discovery document was served (upstream discoveryEndpoint overridden) */
	afterDiscoveryResponse?: (as: Fapi2As) => void;
	/** The use_dpop_nonce response of the resource endpoints (upstream createResourceEndpointDpopErrorResponse); default CreateResourceEndpointDpopErrorResponse */
	createResourceEndpointDpopErrorResponse?: (expectedNonce: string) => DpopErrorResponse;
	/** What the client got that obliges it to stop (upstream getResponseClientMustStopAfter): names the refused requests' reason */
	responseClientMustStopAfter?: string;
}

/** What the PAR request established (upstream "par_endpoint_http_request_params", "authorization_request_object", ...) */
export interface ParState {
	params: ParParams;
	requestObject: ParsedJwt | null;
	/** upstream "authorization_code_dpop_jkt" ("" when the request is not bound) */
	authorizationCodeDpopJkt: string | null;
}

/** What the authorization request established */
export interface Fapi2AuthorizationState {
	/** upstream "effective_authorization_endpoint_request" */
	effective: AuthorizationParams;
	/** upstream "scope" */
	scope: string;
	/** upstream "request_scopes_contain_openid" */
	openidRequested: boolean;
	/** upstream "nonce" */
	nonce: string | null;
	/** upstream "authorization_code" */
	code: string;
	/** upstream "code_challenge" / "code_challenge_method" */
	codeChallenge: CodeChallenge;
	/** upstream "requested_id_token_acr_values" */
	requestedAcrValues: string | null;
}

/** The emulated FAPI 2 authorization server of one test: its state (upstream's environment) and the requests the RP sent */
export interface Fapi2As extends RequestDispatcher<Fapi2Endpoint, Fapi2AsEvents> {
	readonly testName: string;
	readonly variant: Fapi2RpVariant;
	readonly config: TestConfig;
	readonly options: Fapi2AsOptions;
	/** upstream "base_url" */
	readonly baseUrl: string;
	/** upstream "base_mtls_url" */
	readonly baseMtlsUrl: string;
	/** upstream "issuer": base_url + "/" */
	readonly issuer: string;
	/** upstream "discoveryUrl" */
	readonly discoveryUrl: string;
	/** upstream "accounts_endpoint" */
	readonly accountsEndpoint: string;
	/** upstream "server" */
	readonly metadata: ServerMetadata;
	/** upstream "server_jwks" / "server_public_jwks" / "server_encryption_keys" */
	readonly keys: ServerKeys;
	/** upstream "server_alt_jwks" */
	readonly altJwks: Jwks;
	/** upstream "signing_algorithm" */
	readonly signingAlg: string;
	/** upstream "user_info" */
	readonly userInfo: UserInfo;
	/** upstream "client" (the configuration's) */
	readonly client: RpClient;
	/** upstream "client_jwks" / "client_public_jwks" (the client's configured, public keys), null when not used */
	readonly clientKeys: ClientKeys | null;
	/** The DPoP nonces the server currently expects */
	readonly nonces: DpopNonces;
	par: ParState | null;
	authorization: Fapi2AuthorizationState | null;
	/** upstream "dpop_access_token" */
	accessToken: DpopAccessToken | null;
	/** upstream "token_type" */
	tokenType: string | null;
	/** upstream "access_token_expiration" */
	accessTokenExpiration: string | null;
	/** upstream "at_hash" */
	atHash: string | null;
	/** upstream "refresh_token" */
	refreshToken: string | null;
	/** upstream "id_token" (the last one issued) */
	idToken: string | null;
	/** upstream "fapi_interaction_id" */
	fapiInteractionId: string | null;
	/** upstream startingShutdown: every endpoint refuses the next request */
	readonly startingShutdown: boolean;
	/** From now on the client must not call any endpoint (upstream startWaitingForTimeout; the test's waitFor is the timer) */
	startWaitingForTimeout(): void;
	/** The RP under test reported that it finished (its client driver call returned) */
	rpFinished(): void;
}

/** upstream: condition/rs/LoadUserInfo.java */
export function loadUserInfo(): UserInfo {
	const user = userInfoClaimsValues(["sub", "name", "email", "email_verified"]);
	condition("LoadUserInfo").success("Added user information", { user_info: user });
	return user;
}

/** A header read as a string (OIDFJSON.getString): null when absent, an error when repeated */
function header(req: IncomingRequest, name: string): string | null {
	const v = req.headers[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

/**
 * The failure upstream's framework logs when a condition's @PreEnvironment object is missing (the test stops).
 *
 * (what the [pre] checks of AbstractCondition.evaluate log for a missing @PreEnvironment object)
 */
function missingEnvironmentObject(name: string, objectName: string, ...requirements: string[]): never {
	const c: Condition = condition(name, ...requirements);
	c.failure(
		"[pre] Something unexpected happened (this could be caused by something you did wrong, or it may be an issue in the test suite - please review the instructions and your configuration, if you still see a problem please contact certification@oidf.org with the full details) - couldn't find required object in environment before evaluation: " +
			objectName,
		{ expected: objectName },
	);
}

/** A parameter read as a string (OIDFJSON.getString): null when absent, an error when repeated */
function param(params: Record<string, unknown>, name: string): string | null {
	const v = params[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

// ---------------------------------------------------------------------------------------------------------------
// the incoming request

/** The BCP 195 (RFC 9325) recommended TLS 1.2 ciphers, as OpenSSL names them (the suite's server adds the headers) */
const BCP195_CIPHERS = [
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
];

/**
 * The connection the request came over is TLS 1.3, or TLS 1.2 with a cipher BCP 195 recommends.
 *
 * upstream: condition/common/EnsureIncomingTls12WithBCP195SecureCipherOrTls13.java
 * (EnsureIncomingTls12WithSecureCipherOrTls13)
 */
export function ensureIncomingTls12WithBCP195SecureCipherOrTls13(
	req: IncomingRequest,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureIncomingTls12WithBCP195SecureCipherOrTls13", ...requirements);
	const protocol = header(req, "x-ssl-protocol");
	if (!protocol) {
		c.failure("TLS Protocol not found; this header should have been set by the apache proxy");
	}
	if (protocol === "TLSv1.2") {
		const cipher = header(req, "x-ssl-cipher");
		if (!BCP195_CIPHERS.includes(cipher ?? "")) {
			// "actual" here uses the openssl names instead of the standard iana ones
			c.failure("TLS 1.2 in use and cipher is not one recommended by BCP195", {
				expected: BCP195_CIPHERS,
				actual: cipher,
			});
		}
		c.success("TLS 1.2 in use and cipher is one recommended by BCP195", {
			recommended: BCP195_CIPHERS,
			actual: cipher,
		});
		return;
	}
	if (protocol === "TLSv1.3") {
		c.success("Found TLS 1.3 connection");
		return;
	}
	c.failure("TLS version is neither 1.2 nor 1.3", { actual: protocol });
}

// ---------------------------------------------------------------------------------------------------------------
// the resource request headers

/** upstream: condition/rs/ExtractFapiDateHeader.java */
export function extractFapiDateHeader(req: IncomingRequest, ...requirements: string[]): string {
	const c: Condition = condition("ExtractFapiDateHeader", ...requirements);
	const value = header(req, "x-fapi-auth-date");
	if (!value) {
		c.failure("Couldn't find FAPI auth date header");
	}
	// try to parse it to make sure it's in the right format (RFC 1123)
	const rfc1123 =
		/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} (GMT|UT|[+-]\d{4}|[A-Z]{1,4})$/;
	if (!rfc1123.test(value) || Number.isNaN(Date.parse(value))) {
		c.failureFrom("Could not parse FAPI auth date header", new Error("Text '" + value + "' could not be parsed"), {
			fapi_auth_date: value,
		});
	}
	c.success("Found a FAPI auth date header", { fapi_auth_date: value });
	return value;
}

/** upstream: condition/rs/ExtractFapiIpAddressHeader.java */
export function extractFapiIpAddressHeader(req: IncomingRequest, ...requirements: string[]): string {
	const c: Condition = condition("ExtractFapiIpAddressHeader", ...requirements);
	const value = header(req, "x-fapi-customer-ip-address");
	if (!value) {
		c.failure("Couldn't find FAPI ip address header");
	}
	// try to parse it to make sure it's in the right format
	const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
	const ipv6 = value.includes(":") && URL.canParse(`http://[${value}]/`);
	if (!(ipv4 && ipv4.slice(1).every((octet) => Number(octet) <= 255)) && !ipv6) {
		c.failure("Could not parse FAPI ip address header", { fapi_customer_ip_address: value });
	}
	c.success("Found a FAPI ip address header", { fapi_customer_ip_address: value, addr: value });
	return value;
}

/** upstream: condition/rs/ExtractFapiInteractionIdHeader.java */
export function extractFapiInteractionIdHeader(req: IncomingRequest, ...requirements: string[]): string {
	const c: Condition = condition("ExtractFapiInteractionIdHeader", ...requirements);
	const value = header(req, "x-fapi-interaction-id");
	if (!value) {
		c.failure("Couldn't find FAPI interaction ID header");
	}
	c.success("Found a FAPI interaction ID header", { fapi_interaction_id: value });
	return value;
}

/** upstream: condition/as/ValidateFAPIInteractionIdInResourceRequest.java */
export function validateFAPIInteractionIdInResourceRequest(
	interactionId: string | null,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateFAPIInteractionIdInResourceRequest", ...requirements);
	if (!interactionId) {
		c.log("x-fapi-interaction-id not found in resource endpoint request headers");
		return;
	}
	if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(interactionId)) {
		c.failure("Invalid x-fapi-interaction-id in response request headers- not a UUID", {
			interaction_id: interactionId,
		});
	}
	c.success("x-fapi-interaction-id in resource request headers is a valid UUID", { interaction_id: interactionId });
}

/** upstream: condition/as/CreateFapiInteractionIdIfNeeded.java */
export function createFapiInteractionIdIfNeeded(existing: string | null, ...requirements: string[]): string {
	const c: Condition = condition("CreateFapiInteractionIdIfNeeded", ...requirements);
	if (!existing) {
		const fapiInteractionId = randomUUID();
		c.success("Created new FAPI interaction ID", { fapi_interaction_id: fapiInteractionId });
		return fapiInteractionId;
	}
	// if there's an existing one we just leave it there
	c.log({ msg: "Found existing FAPI interaction ID", fapi_interaction_id: existing, result: "INFO" });
	return existing;
}

/** upstream: condition/rs/CreateFAPIAccountEndpointResponse.java */
export function createFAPIAccountEndpointResponse(fapiInteractionId: string | null): {
	response: Record<string, unknown>;
	headers: Record<string, string>;
} {
	const c: Condition = condition("CreateFAPIAccountEndpointResponse");
	const response = { "conformance-test-finished": "true" };
	if (!fapiInteractionId) {
		c.failure("Couldn't find FAPI Interaction ID");
	}
	const headers = { "x-fapi-interaction-id": fapiInteractionId, "content-type": "application/json; charset=UTF-8" };
	c.success("Created account response object", {
		accounts_endpoint_response: response,
		accounts_endpoint_response_headers: headers,
	});
	return { response, headers };
}

// ---------------------------------------------------------------------------------------------------------------
// the server

/** A JSON response with the headers upstream's ResponseEntity carries */
function jsonResponse(body: unknown, status: number, headers: Record<string, string> = {}): Response {
	return Response.json(body, { status, headers });
}

/** The use_dpop_nonce error response of an authorization server endpoint, as upstream sends it */
function dpopErrorResponse(error: DpopErrorResponse): Response {
	return error.body != null
		? jsonResponse(error.body, error.status, error.headers)
		: new Response(null, { status: error.status, headers: error.headers });
}

/**
 * Sets the authorization server up (upstream configure: the discovery document, the keys, the static client, the
 * DPoP nonces) and serves its endpoints on `server`.
 *
 * upstream: fapi2spfinal/AbstractFAPI2SPFinalClientTest.java (configure, handleHttp, handleClientRequestForPath)
 */
export async function startEmulatedFapi2As(
	server: TestServer,
	ctx: { testName: string; variant: Fapi2RpVariant; config: TestConfig },
	options: Fapi2AsOptions = {},
): Promise<Fapi2As> {
	const { variant, config } = ctx;
	for (const [parameter, supported] of [
		["client_auth_type", "private_key_jwt"],
		["sender_constrain", "dpop"],
		["fapi_profile", "plain_fapi"],
		["authorization_request_type", "simple"],
		["grant_management", "disabled"],
	] as const) {
		if (variant[parameter] !== supported) {
			throw new Error(
				`TODO(port): ${parameter}=${variant[parameter]} is not supported by the emulated FAPI 2 authorization server`,
			);
		}
	}
	const isOidc = variant.fapi_client_type === "oidc";
	const jarmMode = variant.fapi_response_mode === "jarm";
	const signedRequest = variant.fapi_request_method === "signed_non_repudiation";
	const requireAuthorizationServerNonce = options.requireAuthorizationServerEndpointDpopNonce ?? true;
	const requireResourceServerNonce = options.requireResourceServerEndpointDpopNonce ?? true;
	const baseUrl = server.baseUrl;
	const baseMtlsUrl = discovery.mtlsBaseUrl(baseUrl);

	// --- configure ---
	// a configuration with mtls_endpoint_aliases in all cases: clients must support it as per RFC 8705 section 5
	const { server: metadata, discoveryUrl } = isOidc
		? discovery.generateServerConfigurationMTLSOpenId(baseUrl, baseMtlsUrl)
		: discovery.generateOauthServerConfigurationMTLS(baseUrl, baseMtlsUrl);
	const issuer = metadata.issuer as string;
	if (isOidc || jarmMode) {
		discovery.addJwksUriToServerConfiguration(metadata, baseUrl);
	}
	// this must come before the response mode steps due to the JARM signing_algorithm dependency (configureServerJWKS)
	let keys: ServerKeys;
	const serverConfig = config["server"];
	if (
		serverConfig != null &&
		typeof serverConfig === "object" &&
		(serverConfig as Record<string, unknown>)["jwks"] != null
	) {
		keys = jwks.loadServerJWKs(config);
		await validateJwks(keys.jwks, "server signing keys", { requirements: ["RFC7517-1.1"], allowPrivateKeys: true });
	} else {
		keys = jwks.fapi2GenerateServerJWKs();
	}
	await soft(() => jwks.augmentRealJwksWithDecoys(keys, "FAPI2-SP-FINAL-5.4.3-3"), "warning");
	const altJwks = jwks.setRsaAltServerJwks(keys);
	// published in all RP tests so the check does not depend on when the client last fetched/cached the JWKS
	jwks.addUnusableKeysToServerPublicJwks(keys, "RFC7517-5");
	discovery.addResponseTypeCodeToServerConfiguration(metadata, "FAPI2-SP-FINAL-5.3.2.2-1");
	discovery.addIssSupportedToServerConfiguration(metadata, "FAPI2-SP-FINAL-5.3.2.2-7");
	discovery.addCodeChallengeMethodToServerConfiguration(metadata, "FAPI2-SP-FINAL-5.3.2.2");
	if (isOidc) {
		discovery.addScopesSupportedOpenIdToServerConfiguration(metadata);
		discovery.addSubjectTypesSupportedToServerConfiguration(metadata, "OIDCD-3");
	}
	// addProfileSpecificServerConfiguration, addAuthCodeGrantServerConfiguration
	const signingAlg = idToken.extractServerSigningAlg(keys.jwks);
	discovery.addIdTokenSigningAlgsToServerConfiguration(metadata, signingAlg);
	if (signedRequest) {
		discovery.fapi2AddRequestObjectSigningAlgValuesSupportedToServerConfiguration(metadata);
	}
	discovery.addDpopSigningAlgValuesSupportedToServerConfiguration(metadata, "DPOP-5.1");
	discovery.setTokenEndpointAuthMethodsSupportedOnly(metadata, "private_key_jwt");
	par.addPARToServerConfiguration(metadata);
	if (jarmMode) {
		jarm.addJARMToServerConfiguration(metadata, signingAlg);
	}
	discovery.fapi2AddTokenEndpointAuthSigningAlgValuesSupportedToServer(metadata);
	// exposeEnvString("discoveryUrl") / ("issuer") and exposePath("accounts_endpoint", ...) only expose values
	const accountsEndpoint = baseUrl + "/" + ACCOUNTS_PATH;

	const dispatcher = createRequestDispatcher<Fapi2Endpoint, Fapi2AsEvents>(server, {
		before: (endpoint, req) => {
			// handleHttp: the TLS checks on every request under the base url (not the OAuth 2.0 well-known document)
			if (!(endpoint === "discovery" && !isOidc)) {
				soft(
					() =>
						ensureIncomingTls12WithBCP195SecureCipherOrTls13(
							req,
							"FAPI2-SP-FINAL-5.2.1-1",
							"FAPI2-SP-FINAL-5.2.1-2",
							"FAPI2-SP-FINAL-5.2.1-3",
						),
					"warning",
				);
				soft(() => ensureIncomingTls13(req, "RFC9325-3.1.1"), "warning");
			}
			if (endpoint !== "discovery" && endpoint !== "jwks") {
				refuseIfStartingShutdown(req.path);
			}
		},
	});

	let startingShutdown = false;
	const as: Fapi2As = {
		testName: ctx.testName,
		variant,
		config,
		options,
		baseUrl,
		baseMtlsUrl,
		issuer,
		discoveryUrl,
		accountsEndpoint,
		metadata,
		keys,
		altJwks,
		signingAlg,
		userInfo: {},
		client: { client_id: "" },
		clientKeys: null,
		nonces: { authorizationServer: null, resourceServer: null },
		par: null,
		authorization: null,
		accessToken: null,
		tokenType: null,
		accessTokenExpiration: null,
		atHash: null,
		refreshToken: null,
		idToken: null,
		fapiInteractionId: null,
		get startingShutdown() {
			return startingShutdown;
		},
		startWaitingForTimeout() {
			startingShutdown = true;
		},
		expect: dispatcher.expect,
		waitFor: dispatcher.waitFor,
		rpFinished: dispatcher.rpFinished,
		received: dispatcher.received,
		discardEvents: dispatcher.discardEvents,
		serve: dispatcher.serve,
	};

	/** upstream refuseIfStartingShutdown: a TestFailureException naming the response the client must have stopped at */
	function refuseIfStartingShutdown(path: string): void {
		if (startingShutdown) {
			failTest(
				"Client has incorrectly called '" +
					path +
					"' after receiving " +
					(options.responseClientMustStopAfter ?? "a response that must cause it to stop interacting with the server"),
			);
		}
	}

	options.adjustServerConfigurationForMtlsEndpointAliasesVariant?.(metadata, as);
	discovery.addConfiguredScopesToServerConfiguration(metadata, config, "OIDCD-3");
	checkServerConfiguration(metadata);
	if (isOidc) {
		discovery.ensureServerConfigurationHasRequiredOidcMetadata(metadata, "OIDCD-3");
	}
	fapi2FinalEnsureMinimumServerKeyLength(keys.jwks, "FAPI2-SP-FINAL-5.4.1-2", "FAPI2-SP-FINAL-5.4.1-3");
	(as as { userInfo: UserInfo }).userInfo = loadUserInfo();

	// configureClients; upstream leaves this block open until the first endpoint's block, so onConfigurationCompleted
	// logs into it too
	await block("Verify configuration of first client", async () => {
		const client = getStaticClientConfiguration(config, "client") as RpClient;
		(as as { client: RpClient }).client = client;
		// usesClientJwks: private_key_jwt (the client authentication key) or a signed request object (its signing key)
		await validateJwks(client["jwks"] as Jwks, "client configuration", { requirements: ["RFC7517-1.1"] });
		const clientKeys = extractJWKsFromStaticClientConfiguration(client["jwks"]);
		(as as { clientKeys: ClientKeys | null }).clientKeys = clientKeys;
		soft(() => checkDistinctKeyIdValueInClientJWKs(clientKeys.jwks, "RFC7517-4.5"));
		fapi2FinalEnsureMinimumClientKeyLength(clientKeys.jwks, "FAPI2-SP-FINAL-5.4.1-2", "FAPI2-SP-FINAL-5.4.1-3");
		// validateClientConfiguration: nothing for plain_fapi
		// onConfigurationCompleted
		if (requireAuthorizationServerNonce) {
			as.nonces.authorizationServer = soft(() => dpop.createAuthorizationServerDpopNonce(), "info") ?? null;
		}
		if (requireResourceServerNonce) {
			as.nonces.resourceServer = soft(() => dpop.createResourceServerDpopNonce(), "info") ?? null;
		}
		options.onConfigurationCompleted?.(as);
	});

	// --- the endpoints ---
	const jtiCache: JtiCache = [];
	const clientAssertionJtis = new Set<string>();
	const usedCodeVerifiers = new Set<string>();
	const client = as.client;

	const unexpectedClaimsRequirements = [
		"RFC6749-4.1.1",
		"OIDCC-3.1.2.1",
		"RFC7636-4.3",
		"OAuth2-RT-2.1",
		"RFC7519-4.1",
		"DPOP-10",
		"RFC8485-4.1",
		"RFC8707-2.1",
		"RFC9396-2",
	];

	/** The headers of a token / PAR response (upstream "token_endpoint_response_headers": x-fapi-interaction-id when known) */
	function interactionIdHeaders(): Record<string, string> {
		return as.fapiInteractionId ? { "x-fapi-interaction-id": as.fapiInteractionId } : {};
	}

	/** upstream "requested_id_token_acr_values" (FAPIValidateRequestObjectIdTokenACRClaims at the PAR endpoint) */
	let requestedAcrValues: string | null = null;

	/** upstream validateRequestObjectCommonChecks + validateRequestObjectForPAREndpointRequest */
	async function validateRequestObjectForPAREndpointRequest(ro: ParsedJwt): Promise<void> {
		requestObject.fapi2ValidateRequestObjectSigningAlg(ro, "FAPI2-SP-FINAL-5.4");
		soft(() => requestObject.fapiValidateRequestObjectMediaType(ro, "JAR-4"), "warning");
		if (isOidc) {
			// validateIdTokenAcrClaims
			const acr = soft(() => requestObject.fapiValidateRequestObjectIdTokenACRClaims(ro, "OIDCC-5.5.1.1"), "info");
			requestedAcrValues = acr ?? null;
		}
		// validateRequestObjectExpNbf
		requestObject.fapiValidateRequestObjectExp(ro, "RFC7519-4.1.4", "FAPI2-MS-ID1-5.3.1-4");
		soft(() => requestObject.fapi1AdvancedValidateRequestObjectNBFClaim(ro, "FAPI2-MS-ID1-5.3.1-3"));
		requestObject.validateRequestObjectClaims(ro, client, issuer);
		requestObject.validateRequestObjectMaxAge(ro, "OIDCC-13.3");
		soft(() => requestObject.ensureNumericRequestObjectClaimsAreNotNull(ro, "OIDCC-13.3"), "warning");
		soft(() => requestObject.ensureRequestObjectDoesNotContainRequestOrRequestUri(ro, "OIDCC-6.1"));
		soft(() => requestObject.ensureRequestObjectDoesNotContainSubWithClientId(ro, client, "JAR-10.8"));
		await requestObject.validateRequestObjectSignature(
			ro,
			as.clientKeys?.publicJwks ?? { keys: [] },
			client,
			"FAPI2-MS-ID1-5.3.1-1",
		);
		// validateRedirectUriInRequestObject
		soft(() => requestObject.ensureMatchingRedirectUriInRequestObject(ro, client));
		par.ensureRequestObjectContainsCodeChallengeWhenUsingPAR(ro, "FAPI2-SP-FINAL-5.3.2.2-5");
	}

	/** upstream issueAccessToken (GenerateDpopAccessToken, GenerateAccessTokenExpiration, CalculateAtHash) */
	async function issueAccessToken(proof: DpopProof): Promise<void> {
		as.accessToken = await dpop.generateDpopAccessToken(proof);
		as.tokenType = "DPoP";
		as.accessTokenExpiration = soft(() => token.generateAccessTokenExpiration(), "info") ?? null;
		as.atHash = idToken.calculateAtHash(as.accessToken.value, signingAlg, "OIDCC-3.3.2.11");
		options.afterAccessTokenIssued?.(as);
	}

	/** upstream issueIdToken(false): prepareIdTokenClaims, signIdToken, encryptIdToken */
	async function issueIdToken(): Promise<string> {
		const claims = idToken.generateIdTokenClaims(
			as.userInfo,
			issuer,
			client.client_id,
			as.authorization?.nonce ?? null,
		);
		// customizeIdTokenClaimsAfterGenerate, getAuthorizationCodeGrantTypeProfileSteps: nothing for plain_fapi
		if (as.atHash == null) {
			skipped("AddAtHashToIdTokenClaims", { string: "at_hash" }, "OIDCC-3.3.2.11");
		} else {
			idToken.addAtHashToIdTokenClaims(claims, as.atHash, "OIDCC-3.3.2.11");
		}
		// customizeIdTokenClaimsAfterHashes: nothing for plain_fapi
		options.addCustomValuesToIdToken?.(claims, as);
		const acr = as.authorization?.requestedAcrValues ?? null;
		if (acr == null) {
			skipped("AddACRClaimToIdTokenClaims", { string: "requested_id_token_acr_values" }, "OIDCC-3.1.3.7-12");
		} else {
			soft(() => idToken.addACRClaimToIdTokenClaims(claims, acr, "OIDCC-3.1.3.7-12"));
		}
		// signIdToken
		let jwt = await idToken.signIdToken(claims, keys.jwks);
		if (options.addCustomSignatureOfIdToken) {
			jwt = await options.addCustomSignatureOfIdToken(jwt, claims, as);
		}
		// encryptIdToken: id_tokens are never encrypted in the FAPI 2 client tests
		as.idToken = jwt;
		options.afterIdTokenIssued?.(as);
		return jwt;
	}

	/** upstream createJARMResponse: generateJARMResponseClaims, SignJARMResponse, encryptJARMResponse */
	async function createJARMResponse(responseParams: Record<string, string>, code: string): Promise<string> {
		const claims = jarm.generateJARMResponseClaims(
			issuer,
			code,
			client.client_id,
			responseParams["state"] ?? null,
			"JARM-2.1.1",
		);
		options.addCustomValuesToJarmResponse?.(claims, as);
		if (options.createJARMResponse) {
			return options.createJARMResponse(claims, as);
		}
		// authorization_signed_response_alg will not be taken into account. signing_algorithm will be used
		const signed = await jarm.signJARMResponse(claims, keys.jwks, "JARM-2.2");
		return jarm.encryptJARMResponseIfConfigured(signed, client);
	}

	/**
	 * upstream checkResourceEndpointRequest(false) with the DPoP helper: the proof and the access token of a
	 * resource request, RequireDpopAccessToken, validateResourceEndpointHeaders
	 */
	async function checkResourceEndpointRequest(req: IncomingRequest): Promise<string | null> {
		const proof = dpop.extractDpopProofFromHeader(req, "DPOP-5");
		// Need to also extract the DPoP Access token for resource requests
		const incomingToken = dpop.extractDpopAccessTokenFromHeader(req, "DPOP-7");
		const nonceError = await dpop.performDpopProofResourceRequestChecks(proof, req, as.nonces, jtiCache);
		await dpop.requireDpopAccessToken(proof, incomingToken, as.accessToken);
		// validateResourceEndpointHeaders
		if (req.headers["x-fapi-auth-date"] == null) {
			skipped(
				"ExtractFapiDateHeader",
				{ element: ["incoming_request", "headers.x-fapi-auth-date"] },
				"FAPI1-BASE-6.2.2-3",
			);
		} else {
			soft(() => extractFapiDateHeader(req, "FAPI1-BASE-6.2.2-3"));
		}
		if (req.headers["x-fapi-customer-ip-address"] == null) {
			skipped(
				"ExtractFapiIpAddressHeader",
				{ element: ["incoming_request", "headers.x-fapi-customer-ip-address"] },
				"FAPI1-BASE-6.2.2-4",
			);
		} else {
			soft(() => extractFapiIpAddressHeader(req, "FAPI1-BASE-6.2.2-4"));
		}
		if (req.headers["x-fapi-interaction-id"] == null) {
			skipped(
				"ExtractFapiInteractionIdHeader",
				{ element: ["incoming_request", "headers.x-fapi-interaction-id"] },
				"FAPI2-IMP-2.1.1",
			);
		} else {
			// an unusable header removes the interaction id upstream keeps (env.removeNativeValue)
			as.fapiInteractionId = soft(() => extractFapiInteractionIdHeader(req, "FAPI2-IMP-2.1.1")) ?? null;
		}
		soft(() => validateFAPIInteractionIdInResourceRequest(as.fapiInteractionId, "CID-SP-4.3-9", "FAPI2-IMP-2.1.1"));
		return nonceError;
	}

	/** The use_dpop_nonce challenge of a resource endpoint (upstream createResourceEndpointDpopErrorResponse) */
	function resourceEndpointDpopErrorResponse(nonceError: string): Response {
		const create = options.createResourceEndpointDpopErrorResponse ?? dpop.createResourceEndpointDpopErrorResponse;
		const error = soft(() => create(nonceError));
		return error ? dpopErrorResponse(error) : new Response(null, { status: 401 });
	}

	// the endpoints are where the metadata says (relative to the base url, or the OAuth 2.0 well-known document)
	const serve = dispatcher.serve;
	const discoveryPath = discoveryUrl.startsWith(baseUrl + "/")
		? discoveryUrl.substring(baseUrl.length + 1)
		: new URL(discoveryUrl).pathname;
	// the OAuth 2.0 metadata url ends with the base url's trailing slash (GenerateOauthServerConfigurationMTLS); an
	// RFC 8414 client (openid-client) requests it without, which upstream's Spring routing matches too
	const discoveryPaths = [discoveryPath];
	if (discoveryPath.startsWith("/") && discoveryPath.endsWith("/")) {
		discoveryPaths.push(discoveryPath.replace(/\/$/, ""));
	}
	for (const path of discoveryPaths) {
		serve("discovery", path, async (request) => {
			const response = jsonResponse(metadata, 200);
			options.afterDiscoveryResponse?.(as);
			return { response, event: { request } };
		});
	}
	serve("jwks", "jwks", async (request) => ({ response: jsonResponse(keys.publicJwks, 200), event: { request } }));

	serve("par", "par", async (request) =>
		block("PAR endpoint", async () => {
			// authenticateParEndpointRequest
			const assertion = await clientAssertion.validateClientAuthenticationWithPrivateKeyJWT(
				request,
				client,
				metadata,
				clientAssertionJtis,
				{ forParEndpoint: true },
			);
			soft(() =>
				clientAssertion.validateClientAssertionAudClaimIsIssuerAsString(assertion, issuer, "FAPI2-SP-FINAL-5.3.3.1-5"),
			);
			// setParAuthorizationEndpointRequestParamsForHttpMethod
			if (request.method !== "POST") {
				failTest("Got unexpected HTTP method '" + request.method + "' to par endpoint");
			}
			const parParams: ParParams = request.body_form_params ?? {};
			// extractParEndpointRequest
			let ro: ParsedJwt | null = null;
			if (parParams["request"] == null) {
				skipped(
					"ExtractRequestObjectFromPAREndpointRequest",
					{ element: ["par_endpoint_http_request", "body_form_params.request"] },
					"PAR-3",
				);
			} else {
				ro =
					(await soft(() =>
						par.extractRequestObjectFromPAREndpointRequest(request, client, keys.encryptionKeys, "PAR-3"),
					)) ?? null;
			}
			par.ensurePAREndpointRequestDoesNotContainRequestUriParameter(request, "PAR-2.1");
			// additionalParRequestChecks: nothing for plain_fapi
			if (ro?.jwe_header == null) {
				skipped(
					"ValidateEncryptedRequestObjectHasKid",
					{ element: ["authorization_request_object", "jwe_header"] },
					"OIDCC-10.2",
					"OIDCC-10.2.1",
				);
			} else {
				const encrypted = ro;
				soft(() => requestObject.validateEncryptedRequestObjectHasKid(encrypted, "OIDCC-10.2", "OIDCC-10.2.1"));
			}
			if (ro != null) {
				await validateRequestObjectForPAREndpointRequest(ro);
			}
			// checkParRequest (DPoP)
			let proof: DpopProof | null = null;
			let nonceError: string | null = null;
			if (request.headers["dpop"] == null) {
				skipped("ExtractDpopProofFromHeader", { element: ["incoming_request", "headers.dpop"] }, "DPOP-5");
			} else {
				proof = soft(() => dpop.extractDpopProofFromHeader(request, "DPOP-5")) ?? null;
				if (proof != null) {
					nonceError = await dpop.performDpopProofParRequestChecks(proof, request, as.nonces, jtiCache);
				}
			}
			const authorizationCodeDpopJkt =
				soft(() => dpop.extractParAuthorizationCodeDpopBindingKey(ro, parParams, proof, "DPOP-10")) ?? null;
			// validateParRequestInteractionId: nothing for plain_fapi
			as.par = { params: parParams, requestObject: ro, authorizationCodeDpopJkt };

			// the use_dpop_nonce challenge has to come first: it is what makes the client repeat the request with a
			// nonce, and only that repeated request is the one a module's custom error is about
			if (nonceError != null) {
				const error = soft(() => dpop.createPAREndpointDpopErrorResponse(nonceError));
				const response = error ? dpopErrorResponse(error) : new Response(null, { status: 400 });
				return {
					response,
					event: { request, status: response.status, dpopNonceError: nonceError, response: error?.body ?? {} },
				};
			}
			const custom = options.createPAREndpointCustomErrorResponse?.(as) ?? null;
			if (custom != null) {
				return { response: custom, event: { request, status: custom.status, dpopNonceError: null, response: {} } };
			}
			// createPAREndpointResponse
			const created = par.createPAREndpointResponse(as.fapiInteractionId, "PAR-2.2");
			options.addCustomValuesToParResponse?.(created.response, as);
			return {
				response: jsonResponse(created.response, 201, created.headers),
				event: { request, status: 201, dpopNonceError: null, response: created.response },
			};
		}),
	);

	serve("authorization", "authorize", async (request) =>
		block("Authorization endpoint", async () => {
			// setAuthorizationEndpointRequestParamsForHttpMethod
			let httpParams: AuthorizationParams;
			if (request.method === "POST") {
				httpParams = request.body_form_params ?? {};
			} else if (request.method === "GET") {
				httpParams = request.query_string_params;
			} else {
				failTest("Got unexpected HTTP method to authorization endpoint");
			}
			par.ensureAuthorizationRequestDoesNotContainRequestWhenUsingPAR(httpParams);
			soft(() =>
				par.ensureAuthorizationRequestContainsOnlyExpectedParamsWhenUsingPAR(
					httpParams,
					"PAR-4",
					"FAPI2-SP-FINAL-5.3.3.2-6",
				),
			);
			const pushed = as.par;
			const ro = pushed?.requestObject ?? null;
			if (ro?.jwe_header == null) {
				skipped(
					"ValidateEncryptedRequestObjectHasKid",
					{ element: ["authorization_request_object", "jwe_header"] },
					"OIDCC-10.2",
					"OIDCC-10.2.1",
				);
			} else {
				const encrypted = ro;
				soft(() => requestObject.validateEncryptedRequestObjectHasKid(encrypted, "OIDCC-10.2", "OIDCC-10.2.1"));
			}
			if (pushed == null) {
				// UPSTREAM: @PreEnvironment(required = "par_endpoint_http_request_params"): the framework stops the test
				missingEnvironmentObject(
					"CreateEffectiveAuthorizationPARRequestParameters",
					"par_endpoint_http_request_params",
				);
			}
			// CreateEffectiveAuthorizationRequestParameters call must be before endTestIfRequiredParametersAreMissing
			const effective = par.createEffectiveAuthorizationPARRequestParameters(httpParams, pushed.params, ro);
			options.endTestIfRequiredParametersAreMissing?.(effective, as);
			authz.ensureResponseTypeIs(effective, "code", "FAPI2-SP-FINAL-5.3.2.2-1");
			if (ro == null) {
				skipped(
					"CheckForUnexpectedClaimsInRequestObject",
					{ element: ["authorization_request_object", "claims"] },
					...unexpectedClaimsRequirements,
				);
			} else {
				const signed = ro;
				soft(
					() => requestObject.checkForUnexpectedClaimsInRequestObject(signed, ...unexpectedClaimsRequirements),
					"warning",
				);
			}
			// additionalAuthorizationRequestChecks: nothing for plain_fapi
			if (isOidc) {
				const claimsChecks: [
					string,
					(p: AuthorizationParams, ...r: string[]) => void,
					"warning" | "failure",
					string[],
				][] = [
					[
						"CheckForUnexpectedClaimsInClaimsParameter",
						authz.checkForUnexpectedClaimsInClaimsParameter,
						"warning",
						["OIDCC-5.5"],
					],
					[
						"CheckForUnexpectedOpenIdClaims",
						authz.checkForUnexpectedOpenIdClaims,
						"warning",
						["OIDCC-5.1", "OIDCC-5.5.1.1", "BrazilOB-7.2.2-8", "BrazilOB-7.2.2-10", "OBSP-3.4"],
					],
					["CheckRequestClaimsParameterValues", authz.checkRequestClaimsParameterValues, "failure", ["OIDCC-5.5"]],
					[
						"CheckRequestClaimsParameterMemberValues",
						authz.checkRequestClaimsParameterMemberValues,
						"failure",
						["OIDCC-5.5.1"],
					],
				];
				for (const [name, check, severity, requirements] of claimsChecks) {
					if (effective["claims"] == null) {
						skipped(name, { element: ["effective_authorization_endpoint_request", "claims"] }, ...requirements);
					} else {
						soft(() => check(effective, ...requirements), severity);
					}
				}
			} else {
				// this is a failure because it shows an incorrect test configuration
				soft(() => authz.ensureClaimsParameterNotPresentInPlainOAuthRequest(effective));
			}
			const codeChallenge = authz.ensureAuthorizationRequestContainsPkceCodeChallenge(
				effective,
				"FAPI2-SP-FINAL-5.3.3.2-3",
			);
			// validateRequestObjectForAuthorizationEndpointRequest
			if (signedRequest) {
				soft(() => {
					if (ro == null) {
						// UPSTREAM: @PreEnvironment(required = "authorization_request_object")
						missingEnvironmentObject(
							"EnsureClientIdInAuthorizationRequestParametersMatchRequestObject",
							"authorization_request_object",
							"FAPI2-MS-ID1-5.3.2-1",
						);
					}
					authz.ensureClientIdInAuthorizationRequestParametersMatchRequestObject(
						httpParams,
						ro,
						"FAPI2-MS-ID1-5.3.2-1",
					);
				});
			}
			const scope = authz.extractRequestedScopes(effective);
			const openidRequested = scope.split(" ").includes("openid");
			// validateAuthorizationRequestScope
			authz.ensureRequestedScopeIsEqualToConfiguredScope(scope, client);
			if (isOidc) {
				authz.ensureOpenIDInScopeRequest(scope);
			}
			authz.ensureMatchingClientId(client, effective, "OIDCC-3.1.2.1");
			const code = authz.createAuthorizationCode();
			let nonce: string | null = null;
			if (openidRequested) {
				if (!isOidc) {
					failTest("openid scope cannot be used with PLAIN_OAUTH");
				}
				if (effective["nonce"] == null) {
					skipped(
						"ExtractNonceFromAuthorizationRequest",
						{ element: ["effective_authorization_endpoint_request", "nonce"] },
						"OIDCC-3.2.2.1",
					);
				} else {
					nonce = soft(() => authz.extractNonceFromAuthorizationRequest(effective, "OIDCC-3.2.2.1")) ?? null;
				}
			} else {
				if (isOidc) {
					failTest("openid scope must be used with OIDC");
				}
				if (effective["state"] == null) {
					skipped(
						"EnsureAuthorizationRequestContainsStateParameter",
						{ element: ["effective_authorization_endpoint_request", "state"] },
						"RFC6749-4.1.1",
					);
				} else {
					soft(() => authz.ensureAuthorizationRequestContainsStateParameter(effective, "RFC6749-4.1.1"));
				}
			}
			as.authorization = { effective, scope, openidRequested, nonce, code, codeChallenge, requestedAcrValues };
			// customizeAuthorizationEndpoint: nothing for plain_fapi
			// createAuthorizationEndpointResponse
			options.beforeAuthorizationResponse?.(effective, as);
			const responseParams = authz.createAuthorizationEndpointResponseParams(effective);
			authz.addCodeToAuthorizationEndpointResponseParams(responseParams, code, "OIDCC-3.3.2.5");
			authz.addIssToAuthorizationEndpointResponseParams(responseParams, issuer, "FAPI2-SP-FINAL-5.3.2.2-7");
			options.addCustomValuesToAuthorizationResponse?.(responseParams, as);
			let redirect: string;
			let jarmResponse: string | null = null;
			if (jarmMode) {
				jarmResponse = await createJARMResponse(responseParams, code);
				// send via redirect
				redirect = jarm.sendJARMResponseWitResponseModeQuery(
					responseParams,
					jarmResponse,
					"OIDCC-3.3.2.5",
					"JARM-2.3.1",
				);
			} else {
				redirect = authz.sendAuthorizationResponseWithResponseModeQuery(responseParams, "OIDCC-3.1.2.5");
			}
			options.afterAuthorizationResponse?.(as);
			if (requireAuthorizationServerNonce) {
				as.nonces.authorizationServer =
					soft(() => dpop.createAuthorizationServerDpopNonce()) ?? as.nonces.authorizationServer;
			}
			return {
				response: new Response(null, { status: 302, headers: { location: redirect } }),
				event: { request, response: responseParams, redirect, jarmResponse },
			};
		}),
	);

	serve("token", "token", async (request) =>
		block("Token endpoint", async () => {
			soft(() => token.checkClientIdMatchesOnTokenRequestIfPresent(request, client, "RFC6749-3.2.1"));
			const assertion = await clientAssertion.validateClientAuthenticationWithPrivateKeyJWT(
				request,
				client,
				metadata,
				clientAssertionJtis,
			);
			soft(() =>
				clientAssertion.validateClientAssertionAudClaimIsIssuerAsString(assertion, issuer, "FAPI2-SP-FINAL-5.3.3.1-5"),
			);
			// validateTokenRequestInteractionId: nothing for plain_fapi
			// handleTokenEndpointGrantType
			const grantType = param(request.body_form_params ?? {}, "grant_type");
			if (grantType == null) {
				failTest("Token endpoint body does not contain the mandatory 'grant_type' parameter");
			}
			if (grantType !== "authorization_code" && grantType !== "refresh_token") {
				// client_credentials: not supported by the plain_fapi profile
				failTest("Got an unexpected grant type on the token endpoint: " + grantType);
			}
			// checkTokenRequest (DPoP)
			const proof = dpop.extractDpopProofFromHeader(request, "DPOP-5");
			const nonceError = await dpop.performDpopProofTokenRequestChecks(
				proof,
				request,
				as.nonces,
				jtiCache,
				as.par?.authorizationCodeDpopJkt ?? null,
			);
			if (nonceError != null) {
				const error = soft(() => dpop.createTokenEndpointDpopErrorResponse(nonceError));
				const response = error ? dpopErrorResponse(error) : new Response(null, { status: 400 });
				return {
					response,
					event: { request, status: response.status, dpopNonceError: nonceError, response: error?.body ?? {} },
				};
			}
			let idTokenValue: string | null = null;
			if (grantType === "authorization_code") {
				token.validateAuthorizationCode(request, as.authorization?.code ?? null);
				// validateRedirectUriForAuthorizationCodeGrantType
				soft(() => token.validateRedirectUri(request, client));
				token.checkPkceCodeVerifier(request, as.authorization?.codeChallenge as CodeChallenge, usedCodeVerifiers);
				await issueAccessToken(proof);
				token.createRefreshToken(as);
				if (as.authorization?.openidRequested) {
					idTokenValue = await issueIdToken();
				}
			} else {
				token.validateRefreshToken(request, as.refreshToken);
				await issueAccessToken(proof);
				// shouldRotateRefreshTokens: true for plain_fapi
				token.createRefreshToken(as);
				as.idToken = null;
			}
			// createTokenEndpointResponse (no RAR, no grant management, nothing to customize for plain_fapi)
			const accessToken = as.accessToken as DpopAccessToken;
			const response = token.createTokenEndpointResponse(
				{ accessToken: accessToken.value, tokenType: as.tokenType as string, atHash: as.atHash },
				idTokenValue,
				as.authorization?.scope ?? null,
				as.refreshToken,
				as.accessTokenExpiration != null ? Number.parseInt(as.accessTokenExpiration, 10) : null,
				interactionIdHeaders(),
			);
			// Create a new DPoP nonce
			if (requireAuthorizationServerNonce) {
				as.nonces.authorizationServer =
					soft(() => dpop.createAuthorizationServerDpopNonce()) ?? as.nonces.authorizationServer;
			}
			return {
				response: jsonResponse(response, 200, interactionIdHeaders()),
				event: { request, status: 200, dpopNonceError: null, response },
			};
		}),
	);

	serve("userinfo", "userinfo", async (request) => {
		const { nonceError, user } = await block("Userinfo endpoint", async () => {
			const error = await checkResourceEndpointRequest(request);
			const filtered = filterUserInfoForScopes(as.userInfo, as.authorization?.scope ?? "");
			// customizeUserInfoResponse: nothing for plain_fapi
			clearAccessTokenFromRequest();
			return { nonceError: error, user: filtered };
		});
		if (nonceError != null) {
			const response = resourceEndpointDpopErrorResponse(nonceError);
			return { response, event: { request, status: response.status, dpopNonceError: nonceError, response: null } };
		}
		if (requireResourceServerNonce) {
			as.nonces.resourceServer = soft(() => dpop.createResourceServerDpopNonce(), "info") ?? as.nonces.resourceServer;
		}
		// userInfoIsResourceEndpoint: false for plain_fapi, the test goes on
		return { response: jsonResponse(user, 200), event: { request, status: 200, dpopNonceError: null, response: user } };
	});

	serve("accounts", ACCOUNTS_PATH, async (request) => {
		const { nonceError, created } = await block("Accounts endpoint", async () => {
			const error = await checkResourceEndpointRequest(request);
			// validateAccountsEndpointRequest: nothing for plain_fapi
			as.fapiInteractionId = createFapiInteractionIdIfNeeded(as.fapiInteractionId, "FAPI2-IMP-2.1.1");
			const accounts = createFAPIAccountEndpointResponse(as.fapiInteractionId);
			// getAccountsEndpointProfileSteps: nothing for plain_fapi
			clearAccessTokenFromRequest();
			return { nonceError: error, created: accounts };
		});
		if (nonceError != null) {
			const response = resourceEndpointDpopErrorResponse(nonceError);
			return { response, event: { request, status: response.status, dpopNonceError: nonceError, response: null } };
		}
		if (requireResourceServerNonce) {
			as.nonces.resourceServer = soft(() => dpop.createResourceServerDpopNonce(), "info") ?? as.nonces.resourceServer;
		}
		// resourceEndpointCallComplete: at this point the test is fully done (the test's expect("accounts") ends it)
		return {
			response: jsonResponse(created.response, 200, created.headers),
			event: { request, status: 200, dpopNonceError: null, response: created.response },
		};
	});

	return as;
}

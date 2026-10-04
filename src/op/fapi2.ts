/**
 * FAPI 2.0 Security Profile (upstream fapi2spfinal/AbstractFAPI2SPFinalServerTestModule with the plain_fapi
 * FAPI2ProfileBehavior): the OP's configuration, the static clients with their keys, the resource endpoint, the
 * authorization request with PKCE (and the signed request object of signed_non_repudiation), the token request with
 * private_key_jwt + DPoP, the FAPI checks on the token response, and the protected resource request. The pieces that
 * need the browser or several of these together are in tests/fapi2/shared.ts.
 *
 * Ported variants: client_auth_type=private_key_jwt, sender_constrain=dpop, fapi_profile=plain_fapi,
 * authorization_request_type=simple, grant_management=disabled (mTLS, client attestation, RAR, grant management
 * and the ecosystem profiles are not).
 */
import { randomUUID } from "node:crypto";
import { block, condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import type { TestConfig } from "../suite/config.ts";
import { endpointResponse, HttpError, request as httpRequest, type EndpointResponse } from "../suite/http.ts";
import type { Jwks, ParsedJwt } from "../suite/jose.ts";
import * as authz from "./authorization.ts";
import * as discovery from "./discovery.ts";
import * as dpop from "./dpop.ts";
import { ensureHttpStatusCodeIs200or201 } from "./endpoint.ts";
import * as idTokenChecks from "./id-token.ts";
import * as jarm from "./jarm.ts";
import * as jwks from "./jwks.ts";
import type { Fapi2Op, Fapi2Variant } from "./op.ts";
import * as par from "./par.ts";
import * as refresh from "./refresh-token.ts";
import * as registration from "./registration.ts";
import type { Client, ClientKeys } from "./registration.ts";
import * as requestObject from "./request-object.ts";
import * as token from "./token.ts";
import type { AccessToken, TokenRequest, TokenResponse } from "./token.ts";
import { callProtectedResource } from "./userinfo.ts";

/** The FAPI 2 client (upstream env "client" / "client2", "client_jwks", the DPoP key and nonces) */
export interface Fapi2Client extends dpop.DpopClient {
	client: Client;
	keys: ClientKeys;
	dpop: dpop.DpopState;
	/** true for the second client of a multiple-client module (upstream isSecondClient()) */
	second: boolean;
	/** The block name prefix of this client's blocks (upstream currentClientString()) */
	prefix: string;
	/**
	 * What the module changes in the DPoP proofs for each endpoint (upstream createDpopForParEndpointSteps /
	 * createDpopForTokenEndpointSteps / createDpopForResourceEndpointSteps overrides)
	 */
	dpopSteps?: { par?: dpop.DpopProofSteps; token?: dpop.DpopProofSteps; resource?: dpop.DpopProofSteps };
}

/** The protected resource (upstream env "resource" + "protected_resource_url") */
export interface Resource {
	url: string;
	/** `resource.resourceMethod` of the configuration (default GET) */
	method?: string;
}

// ---- configure ----

/**
 * The OP's configuration and keys as upstream's configure() fetches and checks them: the discovery document (an
 * OpenID Connect or OAuth 2.0 one), CheckServerConfiguration, and - with OpenID Connect or JARM - the keys with the
 * FAPI 2.0 key checks. The redirect_uri is created by the caller (CreateRedirectUri) before this.
 *
 * upstream: fapi2spfinal/AbstractFAPI2SPFinalServerTestModule.configure (up to configureClient) with
 * fapi2spfinal/FAPI2ProfileBehavior.fetchServerConfiguration
 */
export async function discoverServer(
	config: TestConfig,
	variant: Pick<Fapi2Variant, "openid" | "fapi_response_mode">,
): Promise<{ metadata: discovery.ServerMetadata; jwks: Jwks | null }> {
	const isOpenId = variant.openid === "openid_connect";
	const jarmMode = variant.fapi_response_mode === "jarm";
	// Make sure we're calling the right server configuration
	const { metadata } = isOpenId
		? await discovery.getDynamicServerConfiguration(config)
		: await discovery.getOauthDynamicServerConfiguration(config);
	// make sure the server configuration passes some basic sanity checks
	discovery.checkServerConfiguration(metadata);
	let serverJwks: Jwks | null = null;
	if (isOpenId || jarmMode) {
		serverJwks = await jwks.fetchServerKeys(metadata);
		soft(() => jwks.checkServerKeysIsValid(serverJwks as Jwks), "warning");
		await jwks.validateJwks(serverJwks, "server JWKS", { requirements: ["RFC7517-1.1"] });
		soft(() => jwks.checkForKeyIdInServerJWKs(serverJwks as Jwks, "OIDCC-10.1"));
		soft(() =>
			jwks.fapi2FinalEnsureMinimumServerKeyLength(serverJwks, "FAPI2-SP-FINAL-5.4.1-2", "FAPI2-SP-FINAL-5.4.1-3"),
		);
	}
	return { metadata, jwks: serverJwks };
}

/**
 * The static client's keys, checked as FAPI 2.0 requires them (a kid on every key, distinct kids, a FAPI 2.0 alg,
 * 2048 / 224 bit keys).
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.validateClientConfiguration (plain_fapi: no profile scope
 * configuration, ValidateClientJWKsPrivatePart) with condition/client/ValidateClientJWKsPrivatePart.java,
 * ExtractJWKsFromStaticClientConfiguration.java, condition/common/CheckForKeyIdInClientJWKs.java,
 * CheckDistinctKeyIdValueInClientJWKs.java, FAPI2CheckKeyAlgInClientJWKs.java,
 * condition/as/FAPI2FinalEnsureMinimumClientKeyLength.java
 */
function validateClientConfiguration(client: Client): ClientKeys {
	registration.validateClientJWKsPrivatePart(client["jwks"], "RFC7517-1.1");
	const keys = registration.extractJWKsFromStaticClientConfiguration(client["jwks"]);
	jwks.checkForKeyIdInClientJWKs(keys.jwks, "OIDCC-10.1");
	soft(() => jwks.checkDistinctKeyIdValueInClientJWKs(keys.jwks, "RFC7517-4.5"));
	soft(() => jwks.fapi2CheckKeyAlgInClientJWKs(keys.jwks, "FAPI2-SP-FINAL-5.4"));
	soft(() =>
		jwks.fapi2FinalEnsureMinimumClientKeyLength(keys.jwks, "FAPI2-SP-FINAL-5.4.1-2", "FAPI2-SP-FINAL-5.4.1-3"),
	);
	return keys;
}

/**
 * The first client: `client` of the configuration with its keys checked.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.configureClient (private_key_jwt + DPoP: no mTLS certificates)
 */
export function configureClient(op: Pick<Fapi2Op, "config">): Fapi2Client {
	const client = registration.getStaticClientConfiguration(op.config, "client");
	const keys = validateClientConfiguration(client);
	return { client, keys, dpop: dpop.newDpopState(), second: false, prefix: "" };
}

/**
 * The second client of a multiple-client module: `client2` of the configuration, checked like the first, with a key
 * different from the first client's.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.configureSecondClient
 */
export async function configureSecondClient(op: Pick<Fapi2Op, "config">, client: Fapi2Client): Promise<Fapi2Client> {
	return block("Verify configuration of second client", async () => {
		const client2 = registration.getStaticClientConfiguration(op.config, "client2");
		const keys = validateClientConfiguration(client2);
		await soft(() => registration.validateClientPrivateKeysAreDifferent(client.client, client2));
		return { client: client2, keys, dpop: dpop.newDpopState(), second: true, prefix: "Second client: " };
	});
}

/** upstream: condition/client/GetResourceEndpointConfiguration.java */
export function getResourceEndpointConfiguration(config: TestConfig): Record<string, unknown> {
	const c: Condition = condition("GetResourceEndpointConfiguration");
	const resource = config["resource"];
	if (resource == null || typeof resource !== "object" || Array.isArray(resource)) {
		c.failure("Couldn't find resource endpoint object in configuration");
	}
	c.success("Found a resource endpoint object", resource as Record<string, unknown>);
	return resource as Record<string, unknown>;
}

/** upstream: condition/client/SetProtectedResourceUrlToSingleResourceEndpoint.java */
export function setProtectedResourceUrlToSingleResourceEndpoint(resource: Record<string, unknown>): string {
	const c: Condition = condition("SetProtectedResourceUrlToSingleResourceEndpoint");
	const resourceUrl = resource["resourceUrl"];
	if (typeof resourceUrl !== "string" || !resourceUrl) {
		c.failure("Missing Resource URL");
	}
	c.success("Set protected resource URL", { protected_resource_url: resourceUrl });
	return resourceUrl;
}

/**
 * The protected resource of the configuration (`resource.resourceUrl`, `resource.resourceMethod`).
 *
 * upstream: FAPI2ProfileBehavior.setupResourceEndpoint (plain_fapi: FAPIResourceConfiguration)
 */
export function setupResourceEndpoint(op: Pick<Fapi2Op, "config">): Resource {
	const resource = getResourceEndpointConfiguration(op.config);
	const url = setProtectedResourceUrlToSingleResourceEndpoint(resource);
	const method = resource["resourceMethod"];
	return { url, method: typeof method === "string" && method ? method : undefined };
}

// ---- the authorization request ----

/** The FAPI 2 authorization request: the OIDCC one plus PKCE and the request object of signed_non_repudiation */
export interface Fapi2AuthorizationRequest extends authz.AuthorizationRequest {
	/**
	 * upstream env "state": CreateRandomStateValue always runs, so a module that leaves the state out of the request
	 * (`omit.state`) still has the value (StateOnlyOutsideRequestObjectNotUsed sends it outside the request object)
	 */
	state: string | null;
	/** The PKCE code_verifier (upstream "code_verifier"), null when the module leaves PKCE out */
	codeVerifier: string | null;
	/**
	 * The request object's claims (upstream "request_object_claims"; with an unsigned request they are the pushed
	 * form parameters, upstream `env.mapKey("request_object_claims", "pushed_authorization_request_form_parameters")`)
	 */
	requestObjectClaims: Record<string, unknown>;
	/** The signed request object (upstream "request_object"), null with fapi_request_method=unsigned */
	requestObject: string | null;
	/** fapi_response_mode=jarm: the response is the `response` JWT */
	jarm: boolean;
}

export interface Fapi2AuthorizationRequestOptions {
	/** upstream CreateAuthorizationRequestSteps `usePkce` (fapi2-security-profile-final-par-ensure-pkce-required: false) */
	usePkce?: boolean;
	/** upstream skip(CreateRandomNonceValue), skip(AddNonceToAuthorizationEndpointRequest): the reasons logged */
	omit?: { state?: string; nonce?: [string, string] };
	/** CreateRandomNonceValue's `requested_nonce_length` (FAPI2SPFinalHappyFlow: 43 for the second client) */
	nonceLength?: number;
	/** Steps the module adds after the standard ones (upstream `.then(condition(...))`); `pkce` is the code_verifier created */
	steps?: (params: Record<string, unknown>, pkce: { codeVerifier: string | null }) => void | Promise<void>;
	/** CreateRandomStateValue's `requested_state_length` (the long state and user-rejects modules; 128 for the second client) */
	stateLength?: number;
	/** upstream `.replace(SetAuthorizationEndpointRequestResponseTypeToCode, condition)` (the response_type modules) */
	responseType?: (params: Record<string, unknown>) => void;
	/** Run before the standard steps (upstream code of a makeCreateAuthorizationRequestSteps override before super) */
	before?: () => void;
}

/**
 * The authorization request of the FAPI 2 modules: client_id, redirect_uri and scope, a random state (128 characters
 * for the second client) and - with OpenID Connect - nonce, response_type=code, response_mode=jwt with JARM, and
 * PKCE (S256). The redirect URL is built after the PAR response (`buildPARRedirect`).
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.CreateAuthorizationRequestSteps (plain_fapi: no profile setup
 * steps, no grant management, no RAR)
 */
export async function createAuthorizationRequest(
	op: Pick<Fapi2Op, "metadata" | "variant">,
	client: Fapi2Client,
	redirectUri: string,
	opts: Fapi2AuthorizationRequestOptions = {},
): Promise<Fapi2AuthorizationRequest> {
	const isOpenId = op.variant.openid === "openid_connect";
	const jarmMode = op.variant.fapi_response_mode === "jarm";
	opts.before?.();
	const params = authz.createAuthorizationEndpointRequestFromClientInformation(client.client, redirectUri);
	const stateLength = opts.stateLength ?? (client.second ? 128 : undefined);
	// upstream `.skip(AddStateToAuthorizationEndpointRequest, reason)` leaves CreateRandomStateValue in place: `state`
	// holds the value either way (upstream env "state")
	const state = authz.createRandomStateValue(stateLength);
	if (opts.omit?.state === undefined) {
		authz.addStateToAuthorizationEndpointRequest(params, state);
	} else {
		condition("AddStateToAuthorizationEndpointRequest").log(opts.omit.state);
	}
	let nonce: string | null = null;
	if (isOpenId) {
		if (opts.omit?.nonce === undefined) {
			nonce = authz.createRandomNonceValue(opts.nonceLength);
			authz.addNonceToAuthorizationEndpointRequest(params, nonce);
		} else {
			condition("CreateRandomNonceValue").log(opts.omit.nonce[0]);
			condition("AddNonceToAuthorizationEndpointRequest").log(opts.omit.nonce[1]);
		}
	}
	if (opts.responseType) {
		opts.responseType(params);
	} else {
		authz.setAuthorizationEndpointRequestResponseTypeToCode(params);
	}
	if (jarmMode) {
		authz.setAuthorizationEndpointRequestResponseModeToJWT(params);
	}
	const codeVerifier = opts.usePkce === false ? null : authz.setupPkceAndAddToAuthorizationRequest(params);
	await opts.steps?.(params, { codeVerifier });
	return {
		params,
		state,
		nonce,
		redirectUri,
		responseType: "code",
		responseMode: "default",
		url: "",
		codeVerifier,
		// the request object is implicitly created by the PAR endpoint, but the redirect builder needs to know what is
		// in the implicit request object
		requestObjectClaims: params,
		requestObject: null,
		jarm: jarmMode,
	};
}

export interface RequestObjectOptions {
	/** upstream `.skip(AddExpToRequestObject, reason)`: the reason logged in its place */
	omitExp?: string;
	/** upstream `.replace(AddExpToRequestObject, condition)` / `.replace(AddAudToRequestObject, condition)` */
	exp?: (claims: Record<string, unknown>) => void;
	aud?: (claims: Record<string, unknown>) => void;
	/** upstream `.skip(AddNbfToRequestObject, reason)`: the reason logged in its place */
	omitNbf?: string;
	/** upstream `.replace(AddNbfToRequestObject, condition)` */
	nbf?: (claims: Record<string, unknown>) => void;
	/** upstream `.insertBefore(SignRequestObject, condition)` */
	beforeSign?: (claims: Record<string, unknown>) => void;
	/** upstream `.replace(SignRequestObject, condition)`: returns the request object */
	sign?: (claims: Record<string, unknown>, client: Fapi2Client) => Promise<string>;
	/** upstream `.insertAfter(SignRequestObject, condition)`: returns the (altered) request object */
	afterSign?: (requestObject: string) => string;
}

/**
 * The signed request object of fapi_request_method=signed_non_repudiation: the request parameters as claims with
 * nbf, exp (5 minutes), aud (the issuer), iss and client_id (and iat for the second client), signed with the
 * client's key (with the JAR media type for the second client).
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.CreateAuthorizationRequestObjectSteps (plain_fapi: not encrypted)
 */
export async function createAuthorizationRequestObject(
	op: Pick<Fapi2Op, "metadata">,
	client: Fapi2Client,
	request: Fapi2AuthorizationRequest,
	opts: RequestObjectOptions = {},
): Promise<void> {
	const claims = requestObject.convertAuthorizationEndpointRequestToRequestObject(request.params);
	if (client.second) {
		requestObject.addIatToRequestObject(claims);
	}
	// mandatory in FAPI2-Message-Signing-Final
	if (opts.omitNbf !== undefined) {
		condition("AddNbfToRequestObject").log(opts.omitNbf);
	} else if (opts.nbf) {
		opts.nbf(claims);
	} else {
		requestObject.addNbfToRequestObject(claims, "FAPI2-MS-ID1-5.3.1-3");
	}
	if (opts.omitExp !== undefined) {
		condition("AddExpToRequestObject").log(opts.omitExp);
	} else if (opts.exp) {
		opts.exp(claims);
	} else {
		requestObject.addExpToRequestObject(claims, "FAPI2-MS-ID1-5.3.1-4");
	}
	if (opts.aud) {
		opts.aud(claims);
	} else {
		requestObject.addAudToRequestObject(claims, op.metadata, "FAPI2-SP-FINAL-5.3.2.1-6");
	}
	// iss is a 'should' in OIDC & jwsreq,
	requestObject.addIssToRequestObject(claims, client.client, "OIDCC-6.1");
	// jwsreq-26 is very explicit that client_id should be both inside and outside the request object
	requestObject.addClientIdToRequestObject(claims, client.client, "JAR-5", "FAPI2-MS-ID1-5.3.2-1");
	request.requestObjectClaims = claims;
	opts.beforeSign?.(claims);
	let signed = opts.sign
		? await opts.sign(claims, client)
		: client.second
			? await requestObject.signRequestObjectIncludeMediaType(claims, client, "JAR-4")
			: await requestObject.signRequestObject(claims, client);
	if (opts.afterSign) {
		signed = opts.afterSign(signed);
	}
	request.requestObject = signed;
}

// ---- the PAR flow ----

/**
 * The PAR request of the variant: the authorization request parameters (unsigned), or the signed request object.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.performAuthorizationFlow (isPar) with
 * condition/client/BuildRequestObjectPostToPAREndpoint.java, BuildUnsignedPAREndpointRequest.java
 */
export function buildPAREndpointRequest(request: Fapi2AuthorizationRequest): par.ParRequest {
	return request.requestObject != null
		? par.buildRequestObjectPostToPAREndpoint(request.requestObject)
		: par.buildUnsignedPAREndpointRequest(request.params);
}

/**
 * The client authentication of a PAR or token request: private_key_jwt with the issuer as audience.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.addClientAuthenticationToTokenEndpointRequest /
 * addClientAuthenticationToPAREndpointRequest (setupPrivateKeyJwt:
 * CreateJWTClientAuthenticationAssertionWithIssAudAndAddToTokenEndpointRequest)
 */
export async function addClientAuthentication(
	op: Pick<Fapi2Op, "metadata" | "variant">,
	req: Pick<TokenRequest, "form">,
	client: Fapi2Client,
	mutation?: token.ClientAssertionMutation,
): Promise<void> {
	if (op.variant.client_auth_type !== "private_key_jwt") {
		throw new Error(`client_auth_type '${op.variant.client_auth_type}' is not ported (only private_key_jwt is)`);
	}
	await token.createJWTClientAuthenticationAssertionWithIssAudAndAddToRequest(op, req, client, mutation);
}

/**
 * Calls the PAR endpoint with client authentication; with DPoP authorization code binding
 * (`useDpopAuthCodeBinding`) a DPoP proof is sent too and a `use_dpop_nonce` error is retried once with the nonce.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.callParEndpointAndStopOnFailure
 */
export async function callParEndpointAndStopOnFailure(
	op: Pick<Fapi2Op, "metadata" | "variant">,
	client: Fapi2Client,
	req: par.ParRequest,
	opts: {
		useDpopAuthCodeBinding?: boolean;
		/** the client authentication of this request (upstream addClientAuthenticationToPAREndpointRequest overrides) */
		addClientAuthentication?: (req: par.ParRequest) => Promise<void>;
		requirements?: string[];
		/** upstream "par_endpoint_http_method" (fapi2-security-profile-final-par-attempt-invalid-http-method: PUT) */
		method?: par.CallPAREndpointOptions["method"];
	} = {},
): Promise<par.ParResponse> {
	const requirements = opts.requirements ?? [];
	const authenticate = opts.addClientAuthentication ?? ((r: par.ParRequest) => addClientAuthentication(op, r, client));
	if (op.variant.sender_constrain === "dpop" && opts.useDpopAuthCodeBinding) {
		const MAX_RETRY = 2;
		let response: par.ParResponse | null = null;
		for (let i = 0; i < MAX_RETRY; i++) {
			await authenticate(req);
			await createDpopForParEndpoint(op, client, req);
			const result = await par.callPAREndpointAllowingDpopNonceError(op, req, client.dpop, ...requirements);
			response = result.response;
			if (!result.nonceError) {
				break;
			}
		}
		return response as par.ParResponse;
	}
	await authenticate(req);
	return par.callPAREndpoint(op, req, { requirements, method: opts.method });
}

/** upstream: AbstractFAPI2SPFinalServerTestModule.createDpopForParEndpoint */
export async function createDpopForParEndpoint(
	op: Pick<Fapi2Op, "metadata">,
	client: Fapi2Client,
	req: par.ParRequest,
): Promise<void> {
	if (client.dpop.key == null) {
		await dpop.generateDpopKey(op.metadata, client);
	}
	await dpop.createParEndpointDpopSteps(op.metadata, client, req, undefined, client.dpopSteps?.par);
}

/**
 * The checks on a successful PAR response: status 201 without error, a valid request_uri, expires_in, JSON; returns
 * the request_uri.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.processParResponse (up to performPARRedirectWithRequestUri)
 */
export function processParResponse(res: par.ParResponse): string {
	par.checkPAREndpointResponse201WithNoError(res, "PAR-2.2", "PAR-2.3", "PAR-2.4");
	par.checkForRequestUriValue(res, "PAR-2.2");
	soft(() => par.checkForPARResponseExpiresIn(res, "PAR-2.2"));
	soft(() => ensureContentTypeJsonOfPar(res));
	const { requestUri } = par.extractRequestUriFromPARResponse(res);
	soft(() => par.ensureMinimumRequestUriEntropy(res, "PAR-2.2", "PAR-7.1", "JAR-10.2"));
	return requestUri;
}

/** EnsureContentTypeJson on the PAR response (upstream maps it to "endpoint_response") */
function ensureContentTypeJsonOfPar(res: par.ParResponse): void {
	const c: Condition = condition("EnsureContentTypeJson");
	const contentType = res.headers["content-type"];
	if (typeof contentType !== "string" || contentType === "") {
		c.failure("Couldn't find content-type header in endpoint_response");
	}
	const mimeType = contentType.split(";")[0].trim();
	if (mimeType !== "application/json") {
		c.failure("Invalid content-type header in endpoint_response", {
			expected: "application/json",
			actual: contentType,
		});
	}
	c.success("endpoint_response Content-Type: header is application/json");
}

/**
 * The redirect to the authorization endpoint with the request_uri: with the duplicated OAuth parameters
 * (BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint, reversed for the second client of the happy flow,
 * with the state exposed for the modules whose request object the OP cannot verify), or only client_id and
 * request_uri (`withoutDuplicates`, PAR-4 / JAR-5).
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.performPARRedirectWithRequestUri (the build part), with
 * FAPI2ProfileBehavior.getBuildRequestObjectByReferenceRedirectCondition
 */
export function buildPARRedirect(
	op: Pick<Fapi2Op, "metadata">,
	request: Fapi2AuthorizationRequest,
	requestUri: string,
	opts: { reorderParameters?: boolean; withoutDuplicates?: boolean; exposeState?: boolean } = {},
	...requirements: string[]
): void {
	request.url = opts.withoutDuplicates
		? requestObject.buildRequestObjectByReferenceRedirectToAuthorizationEndpointWithoutDuplicates(
				op,
				request.params,
				request.requestObjectClaims,
				requestUri,
				...requirements,
			)
		: opts.reorderParameters
			? requestObject.buildRequestObjectByReferenceRedirectToAuthorizationEndpointReorderedParams(
					op,
					request.params,
					request.requestObjectClaims,
					requestUri,
					...requirements,
				)
			: opts.exposeState
				? requestObject.buildRequestObjectByReferenceRedirectToAuthorizationEndpointExposingState(
						op,
						request.params,
						request.requestObjectClaims,
						requestUri,
						request.state,
						...requirements,
					)
				: requestObject.buildRequestObjectByReferenceRedirectToAuthorizationEndpoint(
						op,
						request.params,
						request.requestObjectClaims,
						requestUri,
						...requirements,
					);
}

// ---- the callback ----

/**
 * The authorization response from the redirect: the query (the code flow), or the claims of the JARM `response`
 * JWT after its checks; then the checks that nothing came back in the fragment.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.processCallback (up to onAuthorizationCallbackResponse)
 */
export async function processCallback(
	op: Pick<Fapi2Op, "metadata" | "jwks">,
	client: Fapi2Client,
	request: Fapi2AuthorizationRequest,
	response: authz.AuthorizationResponse,
	opts: { allowPlainErrorResponseForJarm?: boolean } = {},
): Promise<void> {
	if (request.jarm) {
		await processCallbackForJARM(op, client, request, response, opts.allowPlainErrorResponseForJarm === true);
	} else {
		// FAPI2 always requires the auth code flow, use the query as the response
		response.params = response.query;
	}
	soft(() => authz.rejectErrorInUrlFragment(response, "OAuth2-RT-5"));
	soft(() => authz.rejectAuthCodeInUrlFragment(response, "OIDCC-3.3.2.5"));
}

/**
 * For error responses, we allow a JARM response, or an error page or a plain (non-jarm) error response per
 * https://gitlab.com/openid/conformance-suite/-/issues/860
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.processCallbackForJARM
 */
export async function processCallbackForJARM(
	op: Pick<Fapi2Op, "metadata" | "jwks">,
	client: Fapi2Client,
	request: Fapi2AuthorizationRequest,
	response: authz.AuthorizationResponse,
	allowPlainErrorResponseForJarm: boolean,
): Promise<void> {
	const errorParameter = response.query["error"];
	const responseParameter = response.query["response"];
	if (allowPlainErrorResponseForJarm && responseParameter == null && errorParameter != null) {
		// plain error response, no jarm
		response.params = jarm.addPlainErrorResponseAsAuthorizationEndpointResponseForJARM(response);
		return;
	}
	soft(() => jarm.validateJARMFromURLQueryEncryption(response, client.keys.jwks, "JARM-2.2"), "warning");
	const jarmResponse = await jarm.extractJARMFromURLQuery(
		response,
		client,
		"FAPI2-MS-ID1-5.4.2-2",
		"JARM-2.3.4",
		"JARM-2.3.1",
	);
	soft(() => jarm.rejectNonJarmResponsesInUrlQuery(response, request.redirectUri, "JARM-2.1"));
	response.params = jarm.extractAuthorizationEndpointResponseFromJARMResponse(jarmResponse);
	soft(() => jarm.validateJARMResponse(op, client.client, jarmResponse, "JARM-2.4-2", "JARM-2.4-3", "JARM-2.4-4"));
	// plain_fapi: FAPI2ProfileBehavior.validateJarmSigningAlg
	soft(() => jarm.fapi2ValidateJarmSigningAlg(jarmResponse));
	// UPSTREAM: ValidateJARMSigningAlg reads a jws_header that is never set, so it is always skipped
	skipped("ValidateJARMSigningAlg", { element: ["jarm_response", "jws_header"] });
	if (jarmResponse.jwe_header == null) {
		skipped("ValidateJARMEncryptionAlg", { element: ["jarm_response", "jwe_header"] });
		skipped("ValidateJARMEncryptionEnc", { element: ["jarm_response", "jwe_header"] });
	} else {
		soft(() => jarm.validateJARMEncryptionAlg(op, jarmResponse));
		soft(() => jarm.validateJARMEncryptionEnc(op, jarmResponse));
	}
	soft(() => jarm.validateJARMExpRecommendations(jarmResponse, "JARM-2.1"), "warning");
	await soft(() => jarm.validateJARMSignatureUsingKid(jarmResponse, op.jwks as Jwks, "JARM-2.4-5"));
}

/**
 * The checks on a successful authorization response and the authorization code: the registered query parameters
 * came back, nothing in the fragment, no error, no unexpected parameters, state, iss, the code (long and random
 * enough).
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.onAuthorizationCallbackResponse (up to
 * handleSuccessfulAuthorizationEndpointResponse)
 */
export function onAuthorizationCallbackResponse(
	op: Pick<Fapi2Op, "metadata">,
	request: Fapi2AuthorizationRequest,
	response: authz.AuthorizationResponse,
): string {
	soft(() => authz.checkMatchingCallbackParameters(request, response));
	soft(() => authz.rejectStateInUrlFragmentForCodeFlow(response, "OIDCC-3.3.2.5"));
	authz.checkIfAuthorizationEndpointError(response);
	if (request.jarm) {
		soft(() => authz.validateSuccessfulJARMResponseFromAuthorizationEndpoint(response), "warning");
	} else {
		soft(() => authz.validateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint(response), "warning");
	}
	soft(() => authz.checkStateInAuthorizationResponse(request, response, "OIDCC-3.2.2.5"));
	soft(() => authz.requireIssInAuthorizationResponse(op, response, "OAuth2-iss-2", "FAPI2-SP-FINAL-5.3.2.2-7"));
	const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
	soft(() => authz.ensureMinimumAuthorizationCodeLength(code, "RFC6749-10.10", "RFC6819-5.1.4.2-2"));
	soft(() => authz.ensureMinimumAuthorizationCodeEntropy(code, "RFC6749-10.10", "RFC6819-5.1.4.2-2"));
	return code;
}

// ---- the token endpoint ----

/**
 * The token request for the code with the PKCE code_verifier (the client authentication is added by
 * callSenderConstrainedTokenEndpoint, per attempt).
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.createAuthorizationCodeRequest (plain_fapi: no profile headers)
 */
export function createAuthorizationCodeRequest(request: Fapi2AuthorizationRequest, code: string): TokenRequest {
	const req = token.createTokenEndpointRequestForAuthorizationCodeGrant(code, request.redirectUri);
	token.addCodeVerifierToTokenEndpointRequest(
		req,
		request.codeVerifier ?? "",
		"RFC7636-4.5",
		"FAPI2-SP-FINAL-5.3.3.2-3",
	);
	return req;
}

/** upstream: AbstractFAPI2SPFinalServerTestModule.createDpopForTokenEndpoint */
export async function createDpopForTokenEndpoint(
	op: Pick<Fapi2Op, "metadata">,
	client: Fapi2Client,
	req: TokenRequest,
): Promise<void> {
	if (client.dpop.key == null) {
		await dpop.generateDpopKey(op.metadata, client);
	}
	await dpop.createTokenEndpointDpopSteps(op.metadata, client, req, client.dpopSteps?.token);
}

/**
 * Calls the token endpoint with the client authentication and a DPoP proof; a `use_dpop_nonce` error is retried
 * once with the server's nonce. Client authentication is added inside the loop so private_key_jwt's client_assertion
 * is regenerated per attempt (the AS may reject reuse of its jti).
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.callSenderConstrainedTokenEndpoint
 */
export async function callSenderConstrainedTokenEndpoint(
	op: Pick<Fapi2Op, "metadata" | "variant">,
	client: Fapi2Client,
	req: TokenRequest,
	opts: {
		/** the client authentication of this request (upstream addClientAuthenticationToTokenEndpointRequest overrides) */
		addClientAuthentication?: (req: TokenRequest) => Promise<void>;
		/** the DPoP proof of this request (upstream createDpopForTokenEndpoint overrides) */
		createDpop?: (req: TokenRequest) => Promise<void>;
		requirements?: string[];
	} = {},
): Promise<TokenResponse> {
	const requirements = opts.requirements ?? [];
	const authenticate = opts.addClientAuthentication ?? ((r: TokenRequest) => addClientAuthentication(op, r, client));
	if (op.variant.sender_constrain === "dpop") {
		const MAX_RETRY = 2;
		let response: TokenResponse | null = null;
		for (let i = 0; i < MAX_RETRY; i++) {
			await authenticate(req);
			if (opts.createDpop) {
				await opts.createDpop(req);
			} else {
				await createDpopForTokenEndpoint(op, client, req);
			}
			const result = await dpop.callTokenEndpointAllowingDpopNonceError(op, req, client.dpop, ...requirements);
			response = result.response;
			if (!result.nonceError) {
				break;
			}
		}
		return response as TokenResponse;
	}
	await authenticate(req);
	return token.callTokenEndpoint(op, req, { requirements });
}

/** What the FAPI 2 token response gave (upstream env "access_token", "refresh_token", "id_token", "token_endpoint_response") */
export interface Fapi2Tokens {
	response: TokenResponse;
	accessToken: AccessToken;
	expiresIn: unknown;
	refreshToken: string | undefined;
	/** null with openid=plain_oauth */
	idToken: ParsedJwt | null;
	/** The id_token claims ValidateIdTokenStandardClaims did not know (upstream "id_token_unknown_claims") */
	idTokenUnknownClaims: Record<string, unknown> | null;
}

/**
 * The checks on a successful token response: status 200, no error, the access token (long and random enough),
 * expires_in, a refresh token when present, and - with OpenID Connect - the id_token with the standard checks, kid,
 * a FAPI 2.0 alg and the optional c_hash / s_hash / at_hash.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.processTokenEndpointResponse (plain_fapi, not the client
 * credentials grant, no RAR, no grant management)
 */
export async function processTokenEndpointResponse(
	op: Pick<Fapi2Op, "metadata" | "jwks" | "variant">,
	client: Fapi2Client,
	request: Fapi2AuthorizationRequest,
	response: TokenResponse,
	code: string | null,
): Promise<Fapi2Tokens> {
	token.checkTokenEndpointHttpStatus200(response);
	token.checkIfTokenEndpointResponseError(response);
	token.checkForAccessTokenValue(response); // RFC6749-4.1.4
	const accessToken = token.extractAccessTokenFromTokenResponse(response);
	const expiresIn = soft(() => token.extractExpiresInFromTokenEndpointResponse(response, "RFC6749-5.1"), "warning");
	if (expiresIn === undefined) {
		skipped("ValidateExpiresIn", { object: "expires_in" }, "RFC6749-5.1");
	} else {
		soft(() => token.validateExpiresIn(expiresIn, "RFC6749-5.1"));
	}
	// scope is not *required* to be returned as the request was passed in signed request object - FAPI-R-5.2.2-15
	// https://gitlab.com/openid/conformance-suite/issues/617
	const refreshToken = soft(() => token.checkForRefreshTokenValue(response), "info");
	if (typeof response.json?.["refresh_token"] !== "string") {
		skipped(
			"EnsureMinimumRefreshTokenLength",
			{ element: ["token_endpoint_response", "refresh_token"] },
			"RFC6749-10.10",
		);
		skipped(
			"EnsureMinimumRefreshTokenEntropy",
			{ element: ["token_endpoint_response", "refresh_token"] },
			"RFC6749-10.10",
		);
	} else {
		soft(() => refresh.ensureMinimumRefreshTokenLength(response, "RFC6749-10.10"));
		soft(() => refresh.ensureMinimumRefreshTokenEntropy(response, "RFC6749-10.10"));
	}
	soft(() => token.ensureMinimumAccessTokenLength(response, "FAPI2-SP-FINAL-5.4.1-4"));
	soft(() => refresh.ensureMinimumAccessTokenEntropy(response, "FAPI2-SP-FINAL-5.4.1-4"));

	let idToken: ParsedJwt | null = null;
	let idTokenUnknownClaims: Record<string, unknown> | null = null;
	if (op.variant.openid === "openid_connect") {
		soft(() => token.validateIdTokenFromTokenResponseEncryption(response, client.keys.jwks, "OIDCC-10.2"), "warning");
		idToken = await token.extractIdTokenFromTokenResponse(response, client, "FAPI2-SP-FINAL-5.3.2.3", "OIDCC-3.3.2.5");
		({ unknownClaims: idTokenUnknownClaims } = await idTokenChecks.performStandardIdTokenChecks(
			{ metadata: op.metadata, jwks: op.jwks as Jwks },
			client.client,
			request,
			idToken,
		));
		soft(() => idTokenChecks.ensureIdTokenContainsKid(idToken as ParsedJwt, "OIDCC-10.1"));
		// plain_fapi: no profile id_token validation steps; FAPI2ProfileBehavior.validateIdTokenSigningAlg
		soft(() => idTokenChecks.fapi2ValidateIdTokenSigningAlg(idToken as ParsedJwt, "FAPI2-SP-FINAL-5.4"));
		// code flow - all hashes are optional.
		const cHash = soft(() => idTokenChecks.extractCHash(idToken as ParsedJwt, "OIDCC-3.3.2.11"), "info");
		const sHash = soft(() => idTokenChecks.extractSHash(idToken as ParsedJwt, "FAPI1-ADV-5.2.2.1-5"), "info");
		const atHash = soft(() => idTokenChecks.extractAtHash(idToken as ParsedJwt, "OIDCC-3.3.2.11"), "info");
		// these all use 'INFO' if the field isn't present - whether the hash is a may/should/shall is determined by
		// the Extract*Hash condition
		if (cHash === undefined) {
			skipped("ValidateCHash", { object: "c_hash" }, "OIDCC-3.3.2.11");
		} else {
			soft(() => idTokenChecks.validateCHash(cHash, code ?? null, "OIDCC-3.3.2.11"));
		}
		if (sHash === undefined) {
			skipped("ValidateSHash", { object: "s_hash" }, "FAPI1-ADV-5.2.2.1-5");
		} else {
			soft(() => idTokenChecks.validateSHash(sHash, request.state ?? null, "FAPI1-ADV-5.2.2.1-5"));
		}
		if (atHash === undefined) {
			skipped("ValidateAtHash", { object: "at_hash" }, "OIDCC-3.3.2.11");
		} else {
			soft(() => idTokenChecks.validateAtHash(atHash, accessToken, "OIDCC-3.3.2.11"));
		}
	} else {
		token.expectNoIdTokenInTokenResponse(response);
	}
	return { response, accessToken, expiresIn, refreshToken, idToken, idTokenUnknownClaims };
}

// ---- the resource endpoint ----

/** upstream: condition/client/CreateEmptyResourceEndpointRequestHeaders.java */
export function createEmptyResourceEndpointRequestHeaders(): Record<string, string> {
	const headers: Record<string, string> = {};
	condition("CreateEmptyResourceEndpointRequestHeaders").log("Created empty headers", {
		resource_endpoint_request_headers: headers,
	});
	return headers;
}

/** upstream: condition/client/AddFAPIAuthDateToResourceEndpointRequest.java */
export function addFAPIAuthDateToResourceEndpointRequest(
	headers: Record<string, string>,
	...requirements: string[]
): void {
	// User just logged in
	headers["x-fapi-auth-date"] = new Date().toUTCString();
	condition("AddFAPIAuthDateToResourceEndpointRequest", ...requirements).success(
		"Added x-fapi-auth-date to resource endpoint request headers",
		{ resource_endpoint_request_headers: { ...headers } },
	);
}

/** upstream: condition/client/AddIpV4FapiCustomerIpAddressToResourceEndpointRequest.java */
export function addIpV4FapiCustomerIpAddressToResourceEndpointRequest(
	headers: Record<string, string>,
	config: TestConfig,
	...requirements: string[]
): void {
	const configured = (config["resource"] as Record<string, unknown> | undefined)?.["x_fapi_customer_ipv4_address"];
	headers["x-fapi-customer-ip-address"] = typeof configured === "string" && configured ? configured : "198.51.100.119";
	condition("AddIpV4FapiCustomerIpAddressToResourceEndpointRequest", ...requirements).log(
		"Added x-fapi-customer-ip-address containing IPv4 address to resource endpoint request headers",
		{ resource_endpoint_request_headers: { ...headers } },
	);
}

/** upstream: condition/client/AddIpV6FapiCustomerIpAddressToResourceEndpointRequest.java */
export function addIpV6FapiCustomerIpAddressToResourceEndpointRequest(
	headers: Record<string, string>,
	config: TestConfig,
	...requirements: string[]
): void {
	// UPSTREAM: reads the IPv4 configuration key
	const configured = (config["resource"] as Record<string, unknown> | undefined)?.["x_fapi_customer_ipv4_address"];
	headers["x-fapi-customer-ip-address"] =
		typeof configured === "string" && configured ? configured : "2001:DB8::1893:25c8:1946";
	condition("AddIpV6FapiCustomerIpAddressToResourceEndpointRequest", ...requirements).log(
		"Added x-fapi-customer-ip-address containing IPv6 address to resource endpoint request headers",
		{ resource_endpoint_request_headers: { ...headers } },
	);
}

/** upstream: condition/client/CreateRandomFAPIInteractionId.java */
export function createRandomFAPIInteractionId(): string {
	const uuid = randomUUID();
	let interactionId = "";
	let toUpper = false;
	// Ensure the hex characters, [a-f], in the UUID are a mix of upper/lower case.
	for (let ch of uuid) {
		if (ch !== ch.toUpperCase()) {
			if (toUpper) {
				ch = ch.toUpperCase();
			}
			toUpper = !toUpper;
		}
		interactionId += ch;
	}
	condition("CreateRandomFAPIInteractionId").log("Created interaction ID", { fapi_interaction_id: interactionId });
	return interactionId;
}

/** upstream: condition/client/AddFAPIInteractionIdToResourceEndpointRequest.java */
export function addFAPIInteractionIdToResourceEndpointRequest(
	headers: Record<string, string>,
	interactionId: string,
	...requirements: string[]
): void {
	headers["x-fapi-interaction-id"] = interactionId;
	condition("AddFAPIInteractionIdToResourceEndpointRequest", ...requirements).success(
		"Added x-fapi-interaction-id to resource endpoint request headers",
		{ resource_endpoint_request_headers: { ...headers } },
	);
}

/** upstream: condition/client/SetUtf8JsonAcceptHeadersForResourceEndpointRequest.java */
export function setUtf8JsonAcceptHeadersForResourceEndpointRequest(headers: Record<string, string>): void {
	// The FAPI1-R implementers draft 2 specs explicitly require the charset UTF8 header
	headers["Accept"] = "application/json;charset=UTF-8";
	headers["Accept-Charset"] = "UTF-8";
	condition("SetUtf8JsonAcceptHeadersForResourceEndpointRequest").success("Set Accept header", {
		Accept: headers["Accept"],
	});
}

/** upstream: condition/client/SetPermissiveAcceptHeaderForResourceEndpointRequest.java */
export function setPermissiveAcceptHeaderForResourceEndpointRequest(headers: Record<string, string>): void {
	headers["Accept"] = "application/json, application/*+json, */*";
	condition("SetPermissiveAcceptHeaderForResourceEndpointRequest").success("Set Accept header", {
		Accept: headers["Accept"],
	});
}

/** upstream: condition/client/ClearAcceptHeaderForResourceEndpointRequest.java */
export function clearAcceptHeaderForResourceEndpointRequest(headers: Record<string, string>): void {
	delete headers["Accept"];
	condition("ClearAcceptHeaderForResourceEndpointRequest").success("Cleared custom Accept header");
}

function headerValue(headers: Record<string, string | string[]>, name: string): string | null {
	const v = headers[name];
	return typeof v === "string" ? v : null;
}

/** upstream: condition/client/CheckForDateHeaderInResourceResponse.java */
export function checkForDateHeaderInResourceResponse(res: EndpointResponse, ...requirements: string[]): void {
	const c: Condition = condition("CheckForDateHeaderInResourceResponse", ...requirements);
	const dateStr = headerValue(res.headers, "date");
	if (!dateStr) {
		c.failure("Date header not found in resource endpoint response");
	}
	// DateTimeFormatter.RFC_1123_DATE_TIME
	const parsed = Date.parse(dateStr);
	if (Number.isNaN(parsed) || !/^\w{3}, \d{1,2} \w{3} \d{4} \d{2}:\d{2}:\d{2} (GMT|[+-]\d{4})$/.test(dateStr)) {
		c.failureFrom("Invalid date format", new Error("Text '" + dateStr + "' could not be parsed"), { date: dateStr });
	}
	const now = Date.now();
	const tolerance = 5 * 60 * 1000;
	const skew = now - parsed;
	if (now - tolerance < parsed && now + tolerance > parsed) {
		c.success("Date header present and validated", { date: dateStr, skew });
		return;
	}
	c.failure("Excessive difference from current time", { date: dateStr, skew });
}

/** upstream: condition/client/CheckForFAPIInteractionIdInResourceResponse.java */
export function checkForFAPIInteractionIdInResourceResponse(res: EndpointResponse, ...requirements: string[]): void {
	const c: Condition = condition("CheckForFAPIInteractionIdInResourceResponse", ...requirements);
	const interactionId = headerValue(res.headers, "x-fapi-interaction-id");
	if (!interactionId) {
		c.failure("x-fapi-interaction-id not found in resource endpoint response headers");
	}
	// java.util.UUID.fromString: five dash-separated hex groups
	if (!/^[0-9a-fA-F]{1,8}-[0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,12}$/.test(interactionId)) {
		c.failure("Invalid x-fapi-interaction-id - not a UUID", { interaction_id: interactionId });
	}
	c.success("Found x-fapi-interaction-id", { interaction_id: interactionId });
}

/** upstream: condition/client/EnsureMatchingFAPIInteractionId.java */
export function ensureMatchingFAPIInteractionId(
	res: EndpointResponse,
	expected: string,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureMatchingFAPIInteractionId", ...requirements);
	const actual = headerValue(res.headers, "x-fapi-interaction-id");
	if (expected && actual != null && expected.toLowerCase() === actual.toLowerCase()) {
		c.success("Interaction ID matches, ignoring case", { fapi_interaction_id: actual });
		return;
	}
	c.failure("Mismatch between interaction IDs", { expected: expected ?? "", actual: actual ?? "" });
}

/**
 * The resource request headers of the first client: x-fapi-auth-date, an IPv4 x-fapi-customer-ip-address and a
 * random x-fapi-interaction-id (the second client sends none).
 *
 * upstream: FAPI2ProfileBehavior.addResourceEndpointProfileHeaders / createDefaultFirstClientResourceHeaders
 */
export function addResourceEndpointProfileHeaders(
	op: Pick<Fapi2Op, "config">,
	client: Fapi2Client,
	headers: Record<string, string>,
): { interactionId: string | null } {
	if (client.second) {
		return { interactionId: null };
	}
	addFAPIAuthDateToResourceEndpointRequest(headers, "CDR-http-headers");
	addIpV4FapiCustomerIpAddressToResourceEndpointRequest(headers, op.config, "CDR-http-headers");
	const interactionId = createRandomFAPIInteractionId();
	addFAPIInteractionIdToResourceEndpointRequest(headers, interactionId, "CID-SP-4.2-12", "CDR-http-headers");
	return { interactionId };
}

/**
 * Calls the resource with a DPoP proof (a new one per attempt), retried once with the resource server's nonce.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.requestProtectedResourceUsingDpop /
 * updateResourceRequestAndCallProtectedResourceUsingDpop (plain_fapi: createUpdateResourceRequestSteps only builds
 * the DPoP proof)
 */
export async function requestProtectedResourceUsingDpop(
	client: Fapi2Client,
	resource: Resource,
	accessToken: AccessToken,
	headers: dpop.DpopRequestHeaders,
	...requirements: string[]
): Promise<EndpointResponse> {
	const MAX_RETRY = 2;
	let response: EndpointResponse | null = null;
	for (let i = 0; i < MAX_RETRY; i++) {
		await dpop.createResourceEndpointDpopSteps(client, resource, accessToken, headers, client.dpopSteps?.resource);
		const result = await dpop.callProtectedResourceAllowingDpopNonceError(resource.url, accessToken, client.dpop, {
			method: resource.method as "GET" | "POST" | undefined,
			headers,
			requirements,
		});
		response = result.response;
		if (!result.nonceError) {
			break; // no nonce error so
		}
		// continue call with nonce
	}
	return response as EndpointResponse;
}

/**
 * Calls the protected resource with the access token (DPoP) and checks the response: status 200 / 201, a Date
 * header and, for the first client, the echoed x-fapi-interaction-id. The caller runs it in the block
 * "Resource server endpoint tests".
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.requestProtectedResource (sender_constrain=dpop, plain_fapi)
 */
export async function requestProtectedResource(
	op: Pick<Fapi2Op, "config" | "variant">,
	client: Fapi2Client,
	resource: Resource,
	accessToken: AccessToken,
): Promise<{ response: EndpointResponse; headers: Record<string, string> }> {
	const headers = createEmptyResourceEndpointRequestHeaders();
	const { interactionId } = addResourceEndpointProfileHeaders(op, client, headers);
	// plain_fapi: no resource request body
	let response: EndpointResponse;
	if (op.variant.sender_constrain === "dpop") {
		response = await requestProtectedResourceUsingDpop(
			client,
			resource,
			accessToken,
			headers,
			"FAPI2-SP-FINAL-5.3.4-2",
		);
	} else {
		response = await callProtectedResource(resource.url, accessToken, {
			method: resource.method as "GET" | "POST" | undefined,
			headers,
			requirements: ["FAPI2-SP-FINAL-5.3.4-2"],
		});
	}
	soft(() => ensureHttpStatusCodeIs200or201(response));
	soft(() => checkForDateHeaderInResourceResponse(response, "RFC7231-7.1.1.2"));
	validateResourceEndpointResponseHeaders(response, interactionId);
	// plain_fapi: no signed response validation
	return { response, headers };
}

/**
 * The x-fapi-interaction-id of the first client's resource response, when the resource server sent one (optional).
 *
 * upstream: FAPI2ProfileBehavior.validateResourceEndpointResponseHeaders
 */
export function validateResourceEndpointResponseHeaders(res: EndpointResponse, interactionId: string | null): void {
	if (interactionId == null) {
		return;
	}
	if (headerValue(res.headers, "x-fapi-interaction-id") == null) {
		skipped(
			"CheckForFAPIInteractionIdInResourceResponse",
			{ element: ["resource_endpoint_response_headers", "x-fapi-interaction-id"] },
			"CID-SP-4.2-12",
			"FAPI2-IMP-2.1.1",
		);
		skipped(
			"EnsureMatchingFAPIInteractionId",
			{ element: ["resource_endpoint_response_headers", "x-fapi-interaction-id"] },
			"CID-SP-4.2-12",
			"FAPI2-IMP-2.1.1",
		);
		return;
	}
	soft(() => checkForFAPIInteractionIdInResourceResponse(res, "CID-SP-4.2-12", "FAPI2-IMP-2.1.1"));
	soft(() => ensureMatchingFAPIInteractionId(res, interactionId, "CID-SP-4.2-12", "FAPI2-IMP-2.1.1"));
}

/**
 * A resource request with the access token only in the URL query (no Authorization header; the other request
 * headers, the DPoP proof among them, as they are) must be refused with 400, 401 or 414.
 *
 * upstream: condition/client/DisallowAccessTokenInQuery.java (AbstractCallProtectedResource)
 */
export async function disallowAccessTokenInQuery(
	resource: Resource,
	accessToken: AccessToken,
	headers: Record<string, string>,
	...requirements: string[]
): Promise<void> {
	const c: Condition = condition("DisallowAccessTokenInQuery", ...requirements);
	if (!accessToken.value) {
		c.failure("Access token not found");
	}
	const url = new URL(resource.url);
	url.searchParams.append("access_token", accessToken.value);
	const method = resource.method || "GET";
	const requestHeaders: Record<string, string> = { ...headers };
	if (!Object.keys(requestHeaders).some((h) => h.toLowerCase() === "accept")) {
		requestHeaders["accept"] = "application/json";
	}
	if (
		["POST", "PUT", "PATCH"].includes(method) &&
		!Object.keys(requestHeaders).some((h) => h.toLowerCase() === "content-type")
	) {
		requestHeaders["content-type"] = "application/x-www-form-urlencoded";
	}
	let res;
	try {
		res = await httpRequest(c.name, { url: url.toString(), method: method as "GET" | "POST", headers: requestHeaders });
	} catch (e) {
		if (e instanceof HttpError) {
			const cause = e.cause instanceof Error ? e.cause.message : null;
			c.failureFrom("Call to protected resource " + url.toString() + " failed" + (cause ? " - " + cause : ""), e);
		}
		throw e;
	}
	if (res.status >= 400) {
		// Java: RestTemplate throws RestClientResponseException on 4xx/5xx
		if (res.status === 400 || res.status === 401 || res.status === 414) {
			c.success("Resource server refused request", { code: res.status, status: res.statusText });
			return;
		}
		c.failure("Unexpected error from the resource endpoint", { code: res.status, status: res.statusText });
	}
	c.failure(
		"Got a successful response from the resource endpoint. An access denied error was expected, as the access token was supplied only in the URL query. Servers are not permitted to accept this for security reasons.",
		{ body: endpointResponse("resource", res).body },
	);
}

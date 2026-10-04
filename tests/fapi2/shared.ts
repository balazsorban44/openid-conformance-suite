/**
 * The bodies of the FAPI 2.0 modules both plans run (the security profile plan is the message signing plan without
 * the signed request object modules), and the pieces of upstream's AbstractFAPI2SPFinalServerTestModule flow the
 * specs share. Each spec registers a shared module under its own title, with its `// upstream:` comment:
 *
 *   // upstream: fapi2spfinal/FAPI2SPFinalHappyFlow.java
 *   test("fapi2-security-profile-final-happy-flow: ...", fapi2HappyFlow);
 *
 * The flow (upstream performAuthorizationFlow .. performPostAuthorizationFlow, with PAR): the authorization request
 * (PKCE; the signed request object with fapi_request_method=signed_non_repudiation), the PAR request with
 * private_key_jwt (and a DPoP proof when the module binds the code to the key), the redirect with the request_uri,
 * the callback (JARM with fapi_response_mode=jarm), the DPoP-bound code exchange and the protected resource request.
 */
import * as authz from "../../src/op/authorization.ts";
import * as discovery from "../../src/op/discovery.ts";
import {
	checkDiscEndpointScopesSupportedContainsRequestedScopes,
	performFapi2EndpointVerification,
} from "../../src/op/discovery-endpoint.ts";
import * as dpop from "../../src/op/dpop.ts";
import {
	ensureHttpStatusCodeIs200or201,
	ensureHttpStatusCodeIs400or401,
	ensureHttpStatusCodeIs4xx,
} from "../../src/op/endpoint.ts";
import * as fapi2 from "../../src/op/fapi2.ts";
import type { Fapi2AuthorizationRequest, Fapi2Client, Fapi2Tokens, Resource } from "../../src/op/fapi2.ts";
import * as idToken from "../../src/op/id-token.ts";
import type { Fapi2Op, Fapi2Variant, OpVariant } from "../../src/op/op.ts";
import * as par from "../../src/op/par.ts";
import * as refresh from "../../src/op/refresh-token.ts";
import * as requestObject from "../../src/op/request-object.ts";
import * as token from "../../src/op/token.ts";
import { block, logModule, skipped, soft } from "../../src/suite/conditions.ts";
import type { TestConfig } from "../../src/suite/config.ts";
import type { EndpointResponse } from "../../src/suite/http.ts";
import { waitFor30Seconds, waitForExpiry, waitForOneSecond } from "../../src/suite/wait.ts";
import { skipTest } from "../fixtures.ts";

/** The fixtures the shared test bodies use */
export type Fapi2Fixtures = { fapi: Fapi2Op };
type ConformanceFixtures = { conformance: { config: TestConfig }; variant: OpVariant };

// ---- the flow ----

export interface AuthorizationFlowOptions {
	/** What the module changes about the authorization request (upstream makeCreateAuthorizationRequestSteps) */
	request?: fapi2.Fapi2AuthorizationRequestOptions;
	/** What the module changes about the request object (upstream makeCreateAuthorizationRequestObjectSteps) */
	requestObject?: fapi2.RequestObjectOptions;
	/** upstream `useDpopAuthCodeBinding`: a DPoP proof with the PAR request (RFC 9449 10) */
	useDpopAuthCodeBinding?: boolean;
	/** The client authentication of the PAR request (upstream addClientAuthenticationToPAREndpointRequest overrides) */
	addClientAuthenticationToPar?: (req: par.ParRequest) => Promise<void>;
	/**
	 * What the module does with the PAR response in place of the standard checks (upstream processParResponse
	 * overrides): returns the request_uri to continue with, or null when the module ends there
	 */
	processParResponse?: (res: par.ParResponse) => string | null;
	/**
	 * The redirect: the duplicated parameters reversed (the happy flow's second client), without them (PAR-4), or
	 * with the state exposed although the request object has it (the modules whose request object the OP cannot
	 * verify; upstream "expose_state_in_authorization_endpoint_request")
	 */
	redirect?: { reorderParameters?: boolean; withoutDuplicates?: boolean; exposeState?: boolean };
	/**
	 * upstream AbstractFAPI2SPFinalExpectingAuthorizationEndpointPlaceholderOrCallback: the module's createPlaceholder;
	 * the OP may answer with an error page (the browser automation screenshots it) instead of a redirect
	 */
	createPlaceholder?: () => string;
	/**
	 * upstream `isSignedRequest`: false sends the request parameters to the PAR endpoint unwrapped even with
	 * fapi_request_method=signed_non_repudiation (ensure-unsigned-request-at-par-endpoint-fails)
	 */
	signedRequest?: boolean;
	/** The module's createAuthorizationRequestObject override, in place of the standard one with `requestObject` */
	createAuthorizationRequestObject?: (request: Fapi2AuthorizationRequest) => Promise<void>;
	/** What the module does before the PAR call (upstream performParAuthorizationRequestFlow overrides calling super) */
	beforePar?: (request: Fapi2AuthorizationRequest, parRequest: par.ParRequest) => void | Promise<void>;
	/**
	 * What the module does before the redirect is built (upstream performPARRedirectWithRequestUri overrides calling
	 * super); `parResponse` for the module that waits for the request_uri to expire
	 */
	beforeRedirect?: (request: Fapi2AuthorizationRequest, parResponse: par.ParResponse) => void | Promise<void>;
	/**
	 * The module's own block for the redirect in place of "Make request to authorization endpoint" (upstream
	 * performPARRedirectWithRequestUri overrides that start their own)
	 */
	redirectBlock?: string;
	/** The requirements the redirect condition cites (PAR-4 by default; a module building the redirect itself cites none) */
	redirectRequirements?: string[];
	/**
	 * The module's performRedirect override: the browser's trip(s) to the authorization endpoint, returning the
	 * response the redirect_uri got (null for an error page)
	 */
	performRedirect?: (request: Fapi2AuthorizationRequest) => Promise<authz.AuthorizationResponse | null>;
}

export interface AuthorizationFlowResult {
	request: Fapi2AuthorizationRequest;
	parResponse: par.ParResponse;
	/** The request_uri the PAR endpoint returned (upstream "request_uri"), null when the module ended at the PAR response */
	requestUri: string | null;
	/** null when the module ended at the PAR response (`processParResponse`) or the OP showed an error page */
	response: authz.AuthorizationResponse | null;
}

/**
 * upstream AbstractFAPI2SPFinalPARExpectingAuthorizationEndpointPlaceholderOrCallback.processParResponse: the server
 * could reject this at the par endpoint (`processParErrorResponse`, the module ends), or at the authorization endpoint
 */
export function expectingParErrorOrCallback(
	processParErrorResponse: (res: par.ParResponse) => void,
): (res: par.ParResponse) => string | null {
	return (res) => {
		if (res.status >= 200 && res.status < 300) {
			return fapi2.processParResponse(res);
		}
		processParErrorResponse(res);
		return null;
	};
}

/**
 * The authorization request pushed to the PAR endpoint and the redirect to the authorization endpoint with the
 * request_uri, up to the browser coming back (or the OP's error page).
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.performAuthorizationFlow (isPar) with
 * performParAuthorizationRequestFlow, processParResponse, performPARRedirectWithRequestUri
 */
export async function performAuthorizationFlow(
	op: Fapi2Op,
	client: Fapi2Client,
	redirectUri: string,
	opts: AuthorizationFlowOptions = {},
): Promise<AuthorizationFlowResult> {
	const prefix = client.prefix;
	// plain_fapi: no pre-authorization steps
	const request = await createAuthorizationRequest(op, client, redirectUri, opts);

	const { parResponse, requestUri } = await block(prefix + "Make request to PAR endpoint", async () => {
		const parRequest = fapi2.buildPAREndpointRequest(request);
		if (request.requestObject == null) {
			// the request object is implicitly created by the PAR endpoint, but the redirect builder needs to know what
			// is in the implicit request object (upstream maps "request_object_claims" to the pushed form parameters)
			request.requestObjectClaims = parRequest.form;
		}
		await opts.beforePar?.(request, parRequest);
		// plain_fapi: no PAR endpoint profile headers; private_key_jwt: no mTLS authentication to leave out
		const res = await fapi2.callParEndpointAndStopOnFailure(op, client, parRequest, {
			useDpopAuthCodeBinding: opts.useDpopAuthCodeBinding,
			addClientAuthentication: opts.addClientAuthenticationToPar,
			requirements: ["PAR-2.1"],
		});
		const uri = opts.processParResponse ? opts.processParResponse(res) : fapi2.processParResponse(res);
		return { parResponse: res, requestUri: uri };
	});
	if (requestUri == null) {
		return { request, parResponse, requestUri, response: null };
	}

	const redirect = async () => {
		await opts.beforeRedirect?.(request, parResponse);
		fapi2.buildPARRedirect(op, request, requestUri, opts.redirect ?? {}, ...(opts.redirectRequirements ?? ["PAR-4"]));
		if (opts.performRedirect) {
			return opts.performRedirect(request);
		}
		if (opts.createPlaceholder) {
			return authz.authorizeExpectingErrorPageOrRedirect(op, request, opts.createPlaceholder());
		}
		return authz.authorize(op, request);
	};
	// upstream's modules that leave the duplicates out start no block: the redirect stays in the PAR endpoint's
	const response = opts.redirect?.withoutDuplicates
		? await redirect()
		: await block(opts.redirectBlock ?? prefix + "Make request to authorization endpoint", redirect);
	return { request, parResponse, requestUri, response };
}

/**
 * The "Create authorization request" block: the authorization request and, with signed_non_repudiation (unless the
 * module sends it unsigned), the request object.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.performAuthorizationFlow (up to the PAR endpoint)
 */
export async function createAuthorizationRequest(
	op: Fapi2Op,
	client: Fapi2Client,
	redirectUri: string,
	opts: Pick<
		AuthorizationFlowOptions,
		"request" | "requestObject" | "signedRequest" | "createAuthorizationRequestObject"
	> = {},
): Promise<Fapi2AuthorizationRequest> {
	const signed = opts.signedRequest ?? op.variant.fapi_request_method === "signed_non_repudiation";
	return block(client.prefix + "Create authorization request", async () => {
		const created = await fapi2.createAuthorizationRequest(op, client, redirectUri, opts.request);
		if (signed) {
			if (opts.createAuthorizationRequestObject) {
				await opts.createAuthorizationRequestObject(created);
			} else {
				await fapi2.createAuthorizationRequestObject(op, client, created, opts.requestObject);
			}
		}
		return created;
	});
}

/**
 * The checks on the callback: the authorization response (JARM or the query), nothing in the fragment, and the
 * module's checks on it (upstream onAuthorizationCallbackResponse, by default the ones of a successful response
 * that return the code).
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.processCallback
 */
export async function verifyAuthorizationResponse(
	op: Fapi2Op,
	client: Fapi2Client,
	request: Fapi2AuthorizationRequest,
	response: authz.AuthorizationResponse,
	opts: {
		allowPlainErrorResponseForJarm?: boolean;
		/** the module's onAuthorizationCallbackResponse: the code, or null when the module ends there */
		onAuthorizationCallbackResponse?: (response: authz.AuthorizationResponse) => string | null;
	} = {},
): Promise<string | null> {
	return block(client.prefix + "Verify authorization endpoint response", async () => {
		await fapi2.processCallback(op, client, request, response, {
			allowPlainErrorResponseForJarm: opts.allowPlainErrorResponseForJarm,
		});
		return opts.onAuthorizationCallbackResponse
			? opts.onAuthorizationCallbackResponse(response)
			: fapi2.onAuthorizationCallbackResponse(op, request, response);
	});
}

export interface TokenEndpointOptions {
	/** The client authentication of the token request (upstream addClientAuthenticationToTokenEndpointRequest overrides) */
	addClientAuthentication?: (req: token.TokenRequest) => Promise<void>;
	requirements?: string[];
}

/**
 * The code exchange: the token request with the code verifier, the client authentication and the DPoP proof.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.performPostAuthorizationFlow ("Call token endpoint":
 * createAuthorizationCodeRequest, callSenderConstrainedTokenEndpoint)
 */
export async function callTokenEndpoint(
	op: Fapi2Op,
	client: Fapi2Client,
	request: Fapi2AuthorizationRequest,
	code: string,
	opts: TokenEndpointOptions = {},
): Promise<{ tokenRequest: token.TokenRequest; response: token.TokenResponse }> {
	return block(client.prefix + "Call token endpoint", async () => {
		const tokenRequest = fapi2.createAuthorizationCodeRequest(request, code);
		const response = await fapi2.callSenderConstrainedTokenEndpoint(op, client, tokenRequest, opts);
		return { tokenRequest, response };
	});
}

/** upstream: AbstractFAPI2SPFinalServerTestModule.exchangeAuthorizationCode ("Verify token endpoint response") */
export async function verifyTokenEndpointResponse(
	op: Fapi2Op,
	client: Fapi2Client,
	request: Fapi2AuthorizationRequest,
	response: token.TokenResponse,
	code: string,
	/** what the module adds after the standard checks (processTokenEndpointResponse overrides calling super) */
	after?: (tokens: Fapi2Tokens) => void,
): Promise<Fapi2Tokens> {
	return block(client.prefix + "Verify token endpoint response", async () => {
		const tokens = await fapi2.processTokenEndpointResponse(op, client, request, response, code);
		after?.(tokens);
		return tokens;
	});
}

/** upstream: AbstractFAPI2SPFinalServerTestModule.requestProtectedResource ("Resource server endpoint tests") */
export async function requestProtectedResource(
	op: Fapi2Op,
	client: Fapi2Client,
	resource: Resource,
	accessToken: token.AccessToken,
): Promise<{ response: EndpointResponse; headers: Record<string, string> }> {
	return block(client.prefix + "Resource server endpoint tests", () =>
		fapi2.requestProtectedResource(op, client, resource, accessToken),
	);
}

export interface PostAuthorizationFlowResult {
	tokenRequest: token.TokenRequest;
	tokens: Fapi2Tokens;
	/** the resource request's headers (upstream "resource_endpoint_request_headers"), for the requests that reuse them */
	resourceHeaders: Record<string, string>;
}

/**
 * The code exchange with the checks on the token response, then the protected resource request.
 *
 * upstream: AbstractFAPI2SPFinalServerTestModule.performPostAuthorizationFlow
 */
export async function performPostAuthorizationFlow(
	op: Fapi2Op,
	client: Fapi2Client,
	request: Fapi2AuthorizationRequest,
	code: string,
	resource: Resource,
	opts: TokenEndpointOptions & { afterTokenResponse?: (tokens: Fapi2Tokens) => void } = {},
): Promise<PostAuthorizationFlowResult> {
	const { tokenRequest, response } = await callTokenEndpoint(op, client, request, code, opts);
	const tokens = await verifyTokenEndpointResponse(op, client, request, response, code, opts.afterTokenResponse);
	const { headers } = await requestProtectedResource(op, client, resource, tokens.accessToken);
	return { tokenRequest, tokens, resourceHeaders: headers };
}

/**
 * A module's whole flow when nothing goes wrong: the authorization flow, the callback checks, the code exchange and
 * the resource request (upstream start() up to onPostAuthorizationFlowComplete).
 */
export async function performCompleteFlow(
	op: Fapi2Op,
	client: Fapi2Client,
	redirectUri: string,
	resource: Resource,
	opts: AuthorizationFlowOptions & TokenEndpointOptions & { afterTokenResponse?: (tokens: Fapi2Tokens) => void } = {},
): Promise<PostAuthorizationFlowResult & { request: Fapi2AuthorizationRequest }> {
	const { request, response } = await performAuthorizationFlow(op, client, redirectUri, opts);
	if (response == null) {
		throw new Error("unreachable: the flow only ends early with processParResponse / createPlaceholder");
	}
	const code = (await verifyAuthorizationResponse(op, client, request, response)) as string;
	return { request, ...(await performPostAuthorizationFlow(op, client, request, code, resource, opts)) };
}

/**
 * The second client's setup: a redirect_uri with a query (which must be registered for it), unless the
 * configuration disables that test.
 *
 * upstream: AbstractFAPI2SPFinalMultipleClient.performAuthorizationFlowWithSecondClient (the "Setup" block)
 */
export async function setUpSecondClientRedirectUri(op: Fapi2Op, client2: Fapi2Client): Promise<string> {
	return block(client2.prefix + "Setup", () => {
		const disabled = op.config["disableRedirectQueryTest"];
		let suffix: string | null = null;
		if (typeof disabled === "number" && disabled !== 0) {
			// Temporary change to allow banks to disable tests until they have had a chance to register new clients
			// with the new redirect uris.
			soft(() => authz.redirectQueryTestDisabled("RFC6749-3.1.2"));
		} else {
			suffix = authz.addRedirectUriQuerySuffix("RFC6749-3.1.2");
		}
		return authz.createRedirectUri(op.baseUrl, suffix, "RFC6749-3.1.2");
	});
}

/**
 * The first client's DPoP key must not get it the second client's access token: a 4xx from the resource.
 *
 * upstream: AbstractFAPI2SPFinalMultipleClient.switchToClient1AndTryClient2AccessToken (sender_constrain=dpop)
 */
export async function tryClient1KeyWithClient2AccessToken(
	client: Fapi2Client,
	resource: Resource,
	client2AccessToken: token.AccessToken,
	headers: Record<string, string>,
): Promise<void> {
	await block("Try Client1's DPoP key with Client2's access token", async () => {
		// As per https://datatracker.ietf.org/doc/html/rfc8705#section-3 :
		//   If they do not match, the resource access attempt MUST
		//   be rejected with an error, per [RFC6750], using an HTTP 401 status
		//   code and the "invalid_token" error code.
		// We are somewhat more permissive; historically we permitted any 4xx or 5xx code,
		// and we are not checking the WWW-Authenticate header at all
		const response = await fapi2.requestProtectedResourceUsingDpop(
			client,
			resource,
			client2AccessToken,
			headers,
			"FAPIRW-5.2.2-5",
			"RFC8705-3",
		);
		soft(() => ensureHttpStatusCodeIs4xx(response, "RFC6749-4.1.2", "RFC6750-3.1", "RFC8705-3"));
	});
}

// ---- the modules ----

/** upstream: fapi2spfinal/FAPI2SPFinalDiscoveryEndpointVerification.java */
export async function fapi2DiscoveryEndpointVerification({ conformance, variant }: ConformanceFixtures): Promise<void> {
	const { config } = conformance;
	const fapiVariant = variant as unknown as Fapi2Variant;
	// upstream: FAPI2ProfileBehavior.discoveryFetchServerConfiguration (plain_fapi)
	const isOpenId = fapiVariant.openid === "openid_connect";
	const { metadata, response } = isOpenId
		? await discovery.getDynamicServerConfiguration(config)
		: await discovery.getOauthDynamicServerConfiguration(config);
	const specRequirements = isOpenId ? "OIDCD-4" : "RFC8414-3.2";
	soft(() => discovery.ensureDiscoveryEndpointResponseStatusCodeIs200(response, specRequirements));
	soft(() => discovery.checkDiscoveryEndpointReturnedJsonContentType(response, specRequirements));

	performFapi2EndpointVerification({ metadata, config, variant: fapiVariant });
}

/** upstream: fapi2spfinal/FAPI2SPFinalHappyFlow.java */
export async function fapi2HappyFlow({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const client2 = await fapi2.configureSecondClient(fapi, client);
	const resource = fapi2.setupResourceEndpoint(fapi);
	// onConfigure (plain_fapi: no directory validation, no scope validation)
	if (fapi.metadata["scopes_supported"] == null) {
		skipped(
			"CheckDiscEndpointScopesSupportedContainsRequestedScopes",
			{ element: ["server", "scopes_supported"] },
			"OIDCD-3",
			"RFC8414-2",
		);
	} else {
		soft(
			() =>
				checkDiscEndpointScopesSupportedContainsRequestedScopes(
					fapi.metadata,
					[
						{ key: "client", scope: client.client.scope },
						{ key: "client2", scope: client2.client.scope },
					],
					"OIDCD-3",
					"RFC8414-2",
				),
			"warning",
		);
	}

	// the first client
	const first = await happyFlowClient(fapi, client, fapi.redirectUri, resource, {});
	if (fapi.variant.openid === "openid_connect") {
		soft(
			() => idToken.ensureIdTokenDoesNotContainNonRequestedClaims(first.tokens.idToken as never, first.request),
			"warning",
		);
	}

	// Try the second client
	const redirectUri2 = await setUpSecondClientRedirectUri(fapi, client2);
	const second = await happyFlowClient(fapi, client2, redirectUri2, resource, {
		request: {
			nonceLength: 43,
			// On the second client, exercise RFC 9449 §10.1's dpop_jkt-only PAR shape (no DPoP header, just the form
			// param) — not otherwise covered in the happy flow.
			steps: async (params) => {
				await dpop.generateDpopKey(fapi.metadata, client2);
				dpop.addDpopJktToAuthorizationEndpointRequest(params, client2);
			},
		},
		redirect: { reorderParameters: true },
	});
	await tryClient1KeyWithClient2AccessToken(client, resource, second.tokens.accessToken, second.resourceHeaders);
}

/**
 * One client's pass through the happy flow: the authorization flow, the code exchange and the resource request,
 * with the additional resource endpoint tests for the first client
 */
async function happyFlowClient(
	op: Fapi2Op,
	client: Fapi2Client,
	redirectUri: string,
	resource: Resource,
	opts: AuthorizationFlowOptions,
): Promise<PostAuthorizationFlowResult & { request: Fapi2AuthorizationRequest }> {
	const { request, response } = await performAuthorizationFlow(op, client, redirectUri, opts);
	const code = (await verifyAuthorizationResponse(
		op,
		client,
		request,
		response as authz.AuthorizationResponse,
	)) as string;
	const { tokenRequest, response: tokenResponse } = await callTokenEndpoint(op, client, request, code);
	const tokens = await verifyTokenEndpointResponse(op, client, request, tokenResponse, code);
	// TODO(port): ExtractTLSTestValuesFromResourceConfiguration and the "Resource endpoint TLS test" block
	// (EnsureTLS12RequireBCP195Ciphers, DisallowTLS10, DisallowTLS11, EnsureTLS13OrLater, EnsureTLS13PreferredOverTLS12,
	// RequireOnlyBCP195RecommendedCiphersForTLS12, CheckForBCP195InsecureFAPICiphers) of the first client
	const { headers } = await requestProtectedResource(op, client, resource, tokens.accessToken);
	if (!client.second) {
		await performAdditionalResourceEndpointTests(op, client, resource, tokens.accessToken, headers);
	}
	return { request, tokenRequest, tokens, resourceHeaders: headers };
}

/**
 * The access token must not be accepted in the query, and different valid Accept headers must be.
 *
 * upstream: FAPI2SPFinalHappyFlow.performAdditionalResourceEndpointTests (sender_constrain=dpop, plain_fapi)
 */
async function performAdditionalResourceEndpointTests(
	op: Fapi2Op,
	client: Fapi2Client,
	resource: Resource,
	accessToken: token.AccessToken,
	headers: Record<string, string>,
): Promise<void> {
	// updateResourceRequest: with DPoP a fresh proof (plain_fapi: nothing else)
	await dpop.createResourceEndpointDpopSteps(client, resource, accessToken, headers);
	await soft(() => fapi2.disallowAccessTokenInQuery(resource, accessToken, headers, "FAPI2-SP-FINAL-5.3.4-2"));

	await dpop.createResourceEndpointDpopSteps(client, resource, accessToken, headers);
	fapi2.addIpV6FapiCustomerIpAddressToResourceEndpointRequest(headers, op.config, "FAPI1-BASE-6.2.2-4");
	// try different, valid accept headers to verify server accepts them
	fapi2.setUtf8JsonAcceptHeadersForResourceEndpointRequest(headers);
	let response = await fapi2.requestProtectedResourceUsingDpop(
		client,
		resource,
		accessToken,
		headers,
		"FAPI2-SP-FINAL-5.3.4-2",
	);
	soft(() => ensureHttpStatusCodeIs200or201(response));

	await dpop.createResourceEndpointDpopSteps(client, resource, accessToken, headers);
	fapi2.setPermissiveAcceptHeaderForResourceEndpointRequest(headers);
	response = await fapi2.requestProtectedResourceUsingDpop(
		client,
		resource,
		accessToken,
		headers,
		"FAPI2-SP-FINAL-5.3.4-2",
	);
	soft(() => ensureHttpStatusCodeIs200or201(response));
	fapi2.clearAcceptHeaderForResourceEndpointRequest(headers);
}

/**
 * upstream: fapi2spfinal/FAPI2SPFinalEnsureAuthorizationRequestWithoutStateSuccess.java
 * (AbstractFAPI2SPFinalEnsureRequestObjectWithoutState with the normal redirect)
 */
export async function fapi2EnsureAuthorizationRequestWithoutStateSuccess({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		request: { omit: { state: "NOT adding state to request object" } },
	});
	const code = await verifyAuthorizationResponse(fapi, client, request, response as authz.AuthorizationResponse, {
		onAuthorizationCallbackResponse: (res) => {
			authz.checkMatchingCallbackParameters(request, res);
			authz.checkIfAuthorizationEndpointError(res);
			soft(() => authz.verifyNoStateInAuthorizationResponse(res));
			const extracted = authz.extractAuthorizationCodeFromAuthorizationResponse(res);
			soft(() => authz.ensureMinimumAuthorizationCodeLength(extracted, "RFC6749-10.10", "RFC6819-5.1.4.2-2"));
			soft(() => authz.ensureMinimumAuthorizationCodeEntropy(extracted, "RFC6749-10.10", "RFC6819-5.1.4.2-2"));
			return extracted;
		},
	});
	await performPostAuthorizationFlow(fapi, client, request, code as string, resource);
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureAuthorizationRequestWithoutNonceSuccess.java */
export async function fapi2EnsureAuthorizationRequestWithoutNonceSuccess({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	await performCompleteFlow(fapi, client, fapi.redirectUri, resource, {
		request: { omit: { nonce: ["NOT creating nonce", "NOT adding nonce to request object"] } },
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureOtherScopeOrderSucceeds.java */
export async function fapi2EnsureOtherScopeOrderSucceeds({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	await performCompleteFlow(fapi, client, fapi.redirectUri, resource, {
		request: { steps: (params) => authz.reverseScopeOrderInAuthorizationEndpointRequest(params, "RFC6749-3.3") },
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalAccessTokenTypeHeaderCaseSensitivity.java */
export async function fapi2AccessTokenTypeHeaderCaseSensitivity({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	await performCompleteFlow(fapi, client, fapi.redirectUri, resource, {
		afterTokenResponse: (tokens) => token.setAccessTokenTypeToInvertedCase(tokens.accessToken, "RFC9110-11.1"),
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureClientIdInTokenEndpoint.java (AbstractFAPI2SPFinalPerformTokenEndpoint) */
export async function fapi2EnsureClientIdInTokenEndpoint({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const client2 = await fapi2.configureSecondClient(fapi, client);
	fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri);
	const code = (await verifyAuthorizationResponse(
		fapi,
		client,
		request,
		response as authz.AuthorizationResponse,
	)) as string;

	const { response: tokenResponse } = await callTokenEndpoint(fapi, client, request, code, {
		// Switch to client 2 client: its client_id and a client_assertion for it, signed with client 1's key
		// (upstream maps "client" to "client2" but not "client_jwks")
		addClientAuthentication: (req) =>
			block("Swapping to Client2", async () => {
				token.addClientIdToRequest(req, client2.client, "RFC6749-5.2");
				// For this test, we explicitly add the client ID - so don't do it twice
				await fapi2.addClientAuthentication(fapi, req, { ...client2, keys: client.keys });
			}),
	});
	await block("Verify token endpoint response", () => {
		/* This test ends up using an authorization code for client1.
		 * For private_key_jwt, it passes the client_id and a client_assertion for client 2, but signed using
		 * client1's jwk.
		 *
		 * If we get an error back from the token endpoint server:
		 * - It must be a 'invalid_client' error (assuming the client authentication was checked first)
		 * - It must be a 'invalid_grant' error (assuming the check for the client_id matching the authorization code is performed first).
		 * The specs don't appear to define an order for these two checks. It may have been preferable for this test to only trigger one possible error.
		 */
		soft(() => token.checkTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError(tokenResponse, "RFC6749-5.2"));
		soft(() => token.checkTokenEndpointReturnedJsonContentType(tokenResponse, "OIDCC-3.1.3.4"));
		soft(() => token.checkErrorFromTokenEndpointResponseErrorInvalidClientOrInvalidGrant(tokenResponse, "RFC6749-5.2"));
		soft(() => token.validateErrorFromTokenEndpointResponseError(tokenResponse, "RFC6749-5.2"));
		token.validateTokenEndpointErrorFields(tokenResponse);
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureHolderOfKeyRequired.java (client_auth_type=private_key_jwt, sender_constrain=dpop) */
export async function fapi2EnsureHolderOfKeyRequired({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	// TODO(port): ExtractTLSTestValuesFromServerConfiguration and the "Authorization endpoint TLS test", "Userinfo
	// Endpoint TLS test", "Token Endpoint TLS test" and "Registration Endpoint TLS test" blocks
	// (EnsureTLS12RequireBCP195Ciphers, DisallowTLS10, DisallowTLS11, EnsureTLS13OrLater, EnsureTLS13PreferredOverTLS12,
	// RequireOnlyBCP195RecommendedCiphersForTLS12, CheckForBCP195InsecureFAPICiphers)
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri);
	const code = (await verifyAuthorizationResponse(
		fapi,
		client,
		request,
		response as authz.AuthorizationResponse,
	)) as string;

	const tokenRequest = fapi2.createAuthorizationCodeRequest(request, code);
	// Add client authentication (client_assertion for private_key_jwt) so the server can identify the client, but
	// deliberately omit the holder-of-key / sender-constraining mechanism: the request carries no DPoP proof. That
	// missing holder-of-key mechanism is what this test checks the server rejects.
	await fapi2.addClientAuthentication(fapi, tokenRequest, client);
	const { response: tokenResponse, sslError } = await token.callTokenEndpointAllowingTLSFailure(
		fapi,
		tokenRequest,
		"FAPI2-SP-FINAL-5.3.2.1-6",
	);
	if (sslError || tokenResponse == null) {
		// the ssl connection was dropped; that's an acceptable way for a server to indicate that a TLS client cert
		// is required, so there's no further checks to do
		return;
	}
	soft(() => ensureHttpStatusCodeIs4xx(tokenResponse, "RFC6749-5.2"));
	// these are only warnings to allow for an SSL terminator returning a generic 4xx response due to the missing cert
	soft(() => token.checkTokenEndpointHttpStatus400or401(tokenResponse, "RFC6749-5.2"), "warning");
	const wasJson = soft(() => {
		token.checkTokenEndpointReturnedJsonContentType(tokenResponse, "OIDCC-3.1.3.4");
		return true;
	}, "warning");
	if (wasJson) {
		// used always when DPoP is the holder of key mechanism
		soft(() =>
			token.checkTokenEndpointReturnedInvalidRequestGrantOrDPopProofError(tokenResponse, "RFC6749-5.2", "RFC9449-5"),
		);
		soft(() => token.validateErrorFromTokenEndpointResponseError(tokenResponse, "RFC6749-5.2"));
		token.validateTokenEndpointErrorFields(tokenResponse);
	}
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureAuthorizationCodeIsBoundToClient.java */
export async function fapi2EnsureAuthorizationCodeIsBoundToClient({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const client2 = await fapi2.configureSecondClient(fapi, client);
	fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri);
	const code = (await verifyAuthorizationResponse(
		fapi,
		client,
		request,
		response as authz.AuthorizationResponse,
	)) as string;

	fapi2.createAuthorizationCodeRequest(request, code);
	// Now try with the wrong client (private_key_jwt: no second certificate to extract)
	const tokenRequest = fapi2.createAuthorizationCodeRequest(request, code);
	const tokenResponse = await fapi2.callSenderConstrainedTokenEndpoint(fapi, client2, tokenRequest, {
		requirements: ["FAPI2-SP-FINAL-5.3.2.1-6"],
	});
	token.checkTokenEndpointHttpStatus400(tokenResponse, "OIDCC-3.1.3.4");
	soft(() => token.checkTokenEndpointReturnedJsonContentType(tokenResponse, "OIDCC-3.1.3.4"));
	soft(() => token.checkErrorFromTokenEndpointResponseErrorInvalidGrant(tokenResponse, "RFC6749-5.2"));
	token.validateErrorFromTokenEndpointResponseError(tokenResponse, "RFC6749-5.2");
	soft(
		() => token.checkErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB(tokenResponse, "RFC6749-5.2"),
		"warning",
	);
	token.validateErrorDescriptionFromTokenEndpointResponseError(tokenResponse, "RFC6749-5.2");
	token.validateErrorUriFromTokenEndpointResponseError(tokenResponse, "RFC6749-5.2");
}

/** upstream: fapi2spfinal/FAPI2SPFinalAttemptReuseAuthorizationCodeAfterOneSecond.java (client_auth_type=private_key_jwt) */
export async function fapi2AttemptReuseAuthorizationCodeAfterOneSecond({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	const { tokenRequest, tokens, resourceHeaders } = await performCompleteFlow(fapi, client, fapi.redirectUri, resource);

	await block("Attempting reuse of authorization code", async () => {
		await waitForOneSecond();
		// We're testing that reuse of the _code_ is refused. Reusing the client assertion (only present for
		// private_key_jwt) is also an error, so generate a new one here.
		await fapi2.addClientAuthentication(fapi, tokenRequest, client);
		const response = await fapi2.callSenderConstrainedTokenEndpoint(fapi, client, tokenRequest, {
			requirements: ["FAPI2-SP-FINAL-5.3.2.2-9"],
		});
		// verifyError
		if (response.status === 200) {
			soft(() => token.serverAllowedReusingAuthorizationCode("FAPI2-SP-FINAL-5.3.2.2-9"));
		} else {
			token.checkInvalidGrantErrorResponse(response);
		}
	});
	await block(
		"Testing if access token was revoked after authorization code reuse (the AS 'should' have revoked the access token)",
		async () => {
			const response = await fapi2.requestProtectedResourceUsingDpop(
				client,
				resource,
				tokens.accessToken,
				resourceHeaders,
				"RFC6749-4.1.2",
			);
			soft(() => ensureHttpStatusCodeIs4xx(response, "RFC6749-4.1.2", "RFC6750-3.1"), "warning");
		},
	);
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureClientAssertionInTokenEndpoint.java (AbstractFAPI2SPFinalPerformTokenEndpoint) */
export async function fapi2EnsureClientAssertionInTokenEndpoint({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri);
	const code = (await verifyAuthorizationResponse(
		fapi,
		client,
		request,
		response as authz.AuthorizationResponse,
	)) as string;

	const { response: tokenResponse } = await callTokenEndpoint(fapi, client, request, code, {
		// no client assertion: the client_id only
		addClientAuthentication: async (req) => token.addClientIdToRequest(req, client.client),
	});
	await block("Verify token endpoint response", () => {
		/* If we get an error back from the token endpoint server:
		 * - It must be a 'invalid_client' or 'invalid_request' error
		 */
		soft(() => token.checkTokenEndpointReturnedJsonContentType(tokenResponse, "OIDCC-3.1.3.4"));
		soft(() => token.validateErrorFromTokenEndpointResponseError(tokenResponse, "RFC6749-5.2"));
		token.validateTokenEndpointErrorFields(tokenResponse);
		soft(() => token.checkTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError(tokenResponse, "RFC6749-5.2"));
		soft(() =>
			token.checkErrorFromTokenEndpointResponseErrorInvalidClientOrInvalidRequest(tokenResponse, "RFC6749-5.2"),
		);
	});
}

interface AssertionCase {
	label: string;
	expect: "rejected" | "should_be_accepted" | "must_be_accepted";
	needsRsaKey?: boolean;
	/** applied to the standard client authentication sequence; null means no client assertion is sent */
	mutation: token.ClientAssertionMutation | null;
}

/** upstream: FAPI2SPFinalEnsureInvalidClientAssertionsFail.cases (not the client credentials grant) */
function invalidClientAssertionCases(op: Fapi2Op, client: Fapi2Client): AssertionCase[] {
	// oxlint-disable-next-line unicorn/consistent-function-scoping -- reads with the cases it builds
	const rejected = (label: string, mutation: token.ClientAssertionMutation | null): AssertionCase => ({
		label,
		expect: "rejected",
		mutation,
	});
	const rejectedClaims = (label: string, afterClaims: (claims: Record<string, unknown>) => void): AssertionCase =>
		rejected(label, { afterClaims });
	return [
		rejected("No client assertion", null),
		rejected("client_assertion_type missing", {
			afterAdd: (req) => token.removeClientAssertionTypeFromRequest(req, "RFC7521-4.2"),
		}),
		rejected("client_assertion_type wrong", {
			afterAdd: (req) => token.setClientAssertionTypeToWrongValue(req, "RFC7521-4.2"),
		}),
		rejectedClaims("Client assertion without sub", (claims) =>
			token.removeSubFromClientAssertionClaims(claims, "RFC7523-3"),
		),
		rejectedClaims("Client assertion with wrong sub", (claims) =>
			token.setSubToWrongValueInClientAssertionClaims(claims, "RFC7523-3"),
		),
		rejectedClaims("Client assertion without iss", (claims) =>
			token.removeIssFromClientAssertionClaims(claims, "RFC7523-3"),
		),
		rejectedClaims("Client assertion with wrong iss", (claims) =>
			token.addWrongIssToClientAssertionClaims(claims, "RFC7523-3"),
		),
		rejectedClaims("Client assertion without aud", (claims) =>
			token.removeAudFromClientAssertionClaims(claims, "RFC7523-3"),
		),
		rejectedClaims("Client assertion with unrelated aud", (claims) =>
			token.addWrongAudToClientAssertionClaims(claims, "RFC7523-3", "FAPI2-SP-FINAL-5.3.2.1-8"),
		),
		rejectedClaims("Client assertion with PAR endpoint as aud", (claims) =>
			token.addPAREndpointAsAudToClientAuthenticationAssertionClaims(claims, op, "FAPI2-SP-FINAL-5.3.2.1-8"),
		),
		rejectedClaims("Client assertion with token endpoint as aud", (claims) =>
			token.addTokenEndpointAsAudToClientAuthenticationAssertionClaims(claims, op, "FAPI2-SP-FINAL-5.3.2.1-8"),
		),
		rejectedClaims("Client assertion with array as aud", (claims) =>
			token.addArrayContainingIssuerAndAnotherValueAsAudToClientAuthenticationAssertionClaims(
				claims,
				op,
				"FAPI2-SP-FINAL-5.3.2.1-8",
			),
		),
		rejectedClaims("Client assertion with exp in the past", (claims) =>
			token.addExpIs5MinutesInPastToClientAssertionClaims(claims, "RFC7523-3"),
		),
		rejectedClaims("Client assertion with iat and nbf over 60 seconds in the future", (claims) =>
			token.addIatNbfExpOver60SecondsInTheFutureToClientAuthenticationAssertionClaims(
				claims,
				"RFC7519-4.1.5",
				"RFC7519-4.1.6",
				"FAPI2-SP-FINAL-5.3.2.1",
			),
		),
		{
			label: "Client assertion signed with RS256",
			expect: "rejected",
			needsRsaKey: true,
			mutation: { beforeSign: () => token.changeClientJwksAlgToRS256(client, "FAPI2-SP-FINAL-5.4") },
		},
		rejected("Client assertion with alg none", {
			sign: async (claims) =>
				token.createUnsecuredClientAuthenticationAssertion(claims, "RFC7523-3", "FAPI2-SP-FINAL-5.4"),
		}),
		rejected("Client assertion with invalid signature", {
			afterSign: (clientAssertion) => token.invalidateClientAssertionSignature(clientAssertion, "RFC7523-3"),
		}),
		{
			label: "Client assertion with iat and nbf 8 seconds in the future",
			expect: "should_be_accepted",
			mutation: {
				afterClaims: (claims) =>
					token.addIatNbf8SecondsInTheFutureToClientAuthenticationAssertionClaims(
						claims,
						"RFC7519-4.1.5",
						"RFC7519-4.1.6",
						"FAPI2-SP-FINAL-5.3.2.1",
					),
			},
		},
		{ label: "Valid client assertion", expect: "must_be_accepted", mutation: {} },
	];
}

/** upstream: JWKUtil.getAlgFromClientJwks (the first key's alg) */
function algFromClientJwks(client: Fapi2Client): string | undefined {
	const key = (client.keys.jwks.keys as Record<string, unknown>[])[0];
	return typeof key?.["alg"] === "string" ? key["alg"] : undefined;
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureInvalidClientAssertionsFail.java (the PAR endpoint, not the client credentials grant) */
export async function fapi2EnsureInvalidClientAssertionsFail({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	const request = await block("Create authorization request", async () => {
		const created = await fapi2.createAuthorizationRequest(fapi, client, fapi.redirectUri);
		if (fapi.variant.fapi_request_method === "signed_non_repudiation") {
			await fapi2.createAuthorizationRequestObject(fapi, client, created);
		}
		return created;
	});
	const parRequest = await block("Make request to PAR endpoint", () => fapi2.buildPAREndpointRequest(request));

	// runCases(super::performParAuthorizationRequestFlow)
	for (const assertionCase of invalidClientAssertionCases(fapi, client)) {
		await block(assertionCase.label, async () => {
			if (assertionCase.needsRsaKey && algFromClientJwks(client) !== "PS256") {
				logModule(
					"The client key in the test configuration is not an RSA key, so an RS256 signed assertion cannot be created; not sending this request.",
				);
				return;
			}
			// ChangeClientJwksAlgToRS256 alters the client keys in place
			const clientJwks = structuredClone(client.keys.jwks);
			// The call*Endpoint methods add client authentication inside their DPoP nonce retry loops, so the
			// assertion for the current case is rebuilt, with a fresh jti, on every attempt.
			const res = await fapi2.callParEndpointAndStopOnFailure(fapi, client, parRequest, {
				requirements: ["PAR-2.1"],
				addClientAuthentication: async (req) => {
					token.removeClientAssertionFromRequest(req);
					if (assertionCase.mutation == null) {
						token.addClientIdToRequest(req, client.client);
					} else {
						await token.createJWTClientAuthenticationAssertionWithIssAudAndAddToRequest(
							fapi,
							req,
							client,
							assertionCase.mutation,
						);
					}
				},
			});
			switch (assertionCase.expect) {
				case "rejected":
					soft(() => ensureHttpStatusCodeIs400or401(res, "PAR-2.3", "RFC6749-5.2"));
					soft(() =>
						par.checkErrorFromParEndpointResponseErrorInvalidClientOrInvalidRequest(res, "PAR-2.3", "RFC6749-5.2"),
					);
					break;
				case "should_be_accepted":
					soft(() => par.checkPAREndpointResponse201WithNoError(res, "PAR-2.2", "PAR-2.3"), "warning");
					break;
				case "must_be_accepted":
					par.checkPAREndpointResponse201WithNoError(res, "PAR-2.2", "PAR-2.3");
					break;
			}
			client.keys.jwks = clientJwks;
		});
	}
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureMismatchedDpopJktFails.java */
export async function fapi2EnsureMismatchedDpopJktFails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	// onConfigure: generate DPOP key for use by AddInvalidDpopJktToAuthorizationEndpointRequest
	await dpop.generateDpopKey(fapi.metadata, client);
	await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		request: { steps: (params) => dpop.addInvalidDpopJktToAuthorizationEndpointRequest(params, client) },
		useDpopAuthCodeBinding: true,
		processParResponse: (res) => {
			soft(() => par.ensurePARInvalidRequestOrInvalidDpopProof(res, "DPOP-10.1"));
			return null;
		},
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalRefreshToken.java (client_auth_type=private_key_jwt, sender_constrain=dpop) */
export async function fapi2RefreshToken({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const client2 = await fapi2.configureSecondClient(fapi, client);
	const resource = fapi2.setupResourceEndpoint(fapi);

	await refreshTokenFlow(fapi, client, fapi.redirectUri, resource);
	// Try the second client
	const redirectUri2 = await setUpSecondClientRedirectUri(fapi, client2);
	const second = await refreshTokenFlow(fapi, client2, redirectUri2, resource);

	await tryClient1KeyWithClient2AccessToken(client, resource, second.accessToken, second.resourceHeaders);
	// try client 2's refresh_token with client 1
	await block("Attempting to use refresh_token issued to client 2 with client 1", () =>
		refresh.refreshTokenRequestExpectingErrorSteps(fapi, client, second.refreshToken, {
			// UPSTREAM: isSecondClient() is still true here (the client was switched back without resetting it)
			secondClient: true,
			addClientAuthentication: (req) => fapi2.addClientAuthentication(fapi, req, client),
			dpop: client,
		}),
	);
}

/**
 * One client's pass through the refresh token module: authorize with prompt=consent for offline_access, exchange the
 * code, use the refresh token (and, for the first client, check the refresh token is bound to the client's
 * authentication and its DPoP key), then call the resource with the refreshed access token. Returns the client's
 * latest refresh token and access token.
 *
 * upstream: FAPI2SPFinalRefreshToken.exchangeAuthorizationCode / sendRefreshTokenRequestAndCheckIdTokenClaims
 */
async function refreshTokenFlow(
	op: Fapi2Op,
	client: Fapi2Client,
	redirectUri: string,
	resource: Resource,
): Promise<{ refreshToken: string; accessToken: token.AccessToken; resourceHeaders: Record<string, string> }> {
	const prefix = client.prefix;
	const { request, response } = await performAuthorizationFlow(op, client, redirectUri, {
		request: {
			steps: (params) =>
				authz.addPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess(params, "OIDCC-11"),
		},
	});
	const code = (await verifyAuthorizationResponse(
		op,
		client,
		request,
		response as authz.AuthorizationResponse,
	)) as string;
	const { response: tokenResponse } = await callTokenEndpoint(op, client, request, code);
	const tokens = await verifyTokenEndpointResponse(op, client, request, tokenResponse, code);

	// sendRefreshTokenRequestAndCheckIdTokenClaims
	const issued = await block(prefix + "Check for refresh token", () => {
		const refreshToken = soft(() => refresh.extractRefreshTokenFromTokenResponse(tokens.response), "info");
		//stop if no refresh token is returned
		if (!refreshToken) {
			soft(() => refresh.fapiEnsureServerConfigurationDoesNotSupportRefreshToken(op.metadata, "OIDCD-3"), "warning");
			// This throws an exception: the test will stop here
			skipTest("Refresh tokens cannot be tested. No refresh token was issued.");
		}
		soft(() => discovery.ensureServerConfigurationSupportsRefreshToken(op.metadata, "OIDCD-3"), "warning");
		soft(() => refresh.ensureRefreshTokenContainsAllowedCharactersOnly(tokens.response, "RFC6749-A.17"));
		return refreshToken;
	});
	const stepsOptions: refresh.RefreshTokenStepsOptions = {
		secondClient: client.second,
		addClientAuthentication: (req) => fapi2.addClientAuthentication(op, req, client),
		dpop: client,
	};
	const beforeExtractIdToken =
		op.variant.openid === "openid_connect"
			? undefined
			: (res: token.TokenResponse) => token.expectNoIdTokenInTokenResponse(res);
	// plain_fapi: refresh token rotation is allowed
	let refreshed = await block(prefix + "Refresh Token Request", () =>
		refresh.refreshTokenRequestSteps(op, client, issued, tokens, stepsOptions, beforeExtractIdToken),
	);
	if (refreshed.refreshToken === issued) {
		logModule("Refresh token not rotated. Skipping lost refresh token test.");
	} else {
		// the previous refresh token must still work (a lost response, FAPI 2.0 Security Profile 5.3.2.1-9)
		refreshed = await block(
			prefix + "Refresh Token Request With Previous Token, FAPI 2.0 Security Profile 5.3.2.1-9",
			async () => {
				await waitFor30Seconds(op.config);
				return refresh.refreshTokenRequestSteps(op, client, issued, tokens, stepsOptions, beforeExtractIdToken);
			},
		);
	}
	let latestRefreshToken = refreshed.refreshToken;

	if (!client.second) {
		// RFC 6749 §6 requires confidential clients to authenticate when refreshing an access token.
		await block("Attempting to use the refresh_token without client authentication", async () => {
			const req = refresh.createRefreshTokenRequest(latestRefreshToken);
			refresh.addScopeToTokenEndpointRequest(req, client.client, "RFC6749-6");
			// intentionally no client_assertion; retry once if the AS asks for a nonce (mirrors callSenderConstrainedTokenEndpoint)
			let res: token.TokenResponse | null = null;
			for (let i = 0; i < 2; i++) {
				await fapi2.createDpopForTokenEndpoint(op, client, req);
				const result = await dpop.callTokenEndpointAllowingDpopNonceError(
					op,
					req,
					client.dpop,
					"FAPI2-SP-FINAL-5.3.2.1-6",
				);
				res = result.response;
				if (!result.nonceError) {
					break;
				}
			}
			const tokenRes = res as token.TokenResponse;
			soft(() => token.checkTokenEndpointHttpStatus400or401(tokenRes, "RFC6749-6"));
			soft(() => token.checkTokenEndpointReturnedJsonContentType(tokenRes, "OIDCC-3.1.3.4"));
			soft(() => token.checkTokenEndpointReturnedInvalidClientGrantOrRequestError(tokenRes, "RFC6749-6"));
		});
		// Ensure a sender constrained refresh_token grant attempt, sent without proof of possession, fails.
		await block("Attempting to use an DPOP sender constrained refresh_token without proof of possession", async () => {
			const req = refresh.createRefreshTokenRequest(latestRefreshToken);
			refresh.addScopeToTokenEndpointRequest(req, client.client, "RFC6749-6");
			await fapi2.addClientAuthentication(op, req, client);
			// call token endpoint without DPOP since this part tests response to ensure error was returned
			const res = await token.callTokenEndpoint(op, req);
			token.validateErrorFromTokenEndpointResponseError(res);
			soft(() => token.checkTokenEndpointHttpStatus400(res, "OIDCC-3.1.3.4"));
			soft(() => token.checkTokenEndpointReturnedJsonContentType(res, "OIDCC-3.1.3.4"));
			// RFC 9449 section 5 allows invalid_dpop_proof when a DPoP-sender-constrained token request is sent
			// without a proof, in addition to invalid_request/invalid_grant.
			soft(() => token.checkTokenEndpointReturnedInvalidRequestGrantOrDPopProofError(res, "RFC6749-5.2", "RFC9449-5"));
		});
	}
	// the refreshed access token is the one the resource is called with (upstream maps "access_token" to the second one)
	const { headers } = await requestProtectedResource(op, client, resource, refreshed.accessToken);
	latestRefreshToken = refreshed.refreshToken;
	return { refreshToken: latestRefreshToken, accessToken: refreshed.accessToken, resourceHeaders: headers };
}

/** upstream: fapi2spfinal/FAPI2SPFinalParWithoutDuplicateParameters.java */
export async function fapi2ParWithoutDuplicateParameters({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	await performCompleteFlow(fapi, client, fapi.redirectUri, resource, { redirect: { withoutDuplicates: true } });
}

/**
 * upstream: fapi2spfinal/FAPI2SPFinalPAREnsurePKCERequired.java
 * (AbstractFAPI2SPFinalPARExpectingAuthorizationEndpointPlaceholderOrCallback)
 */
export async function fapi2PAREnsurePKCERequired({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		// it would probably be preferable to use the 'skip' syntax instead of the 'usePkce' flag
		request: { usePkce: false },
		processParResponse: expectingParErrorOrCallback((res) =>
			soft(() => par.ensurePARInvalidRequestError(res, "RFC7636-4.4.1")),
		),
		createPlaceholder: () => authz.expectPkceMissingErrorPage("FAPI2-SP-FINAL-5.3.2.2-5"),
	});
	if (response == null) {
		// the PAR endpoint rejected the request, or the OP showed an error page (its screenshot is in the log)
		return;
	}
	await verifyAuthorizationResponse(fapi, client, request, response, {
		onAuthorizationCallbackResponse: (res) => {
			soft(() => authz.ensureInvalidRequestError(res, "RFC7636-4.4.1"));
			return null;
		},
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureServerAcceptsRequestObjectWithMultipleAud.java */
export async function fapi2EnsureServerAcceptsRequestObjectWithMultipleAud({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	await performCompleteFlow(fapi, client, fapi.redirectUri, resource, {
		requestObject: {
			aud: (claims) => requestObject.addMultipleAudToRequestObject(claims, fapi.metadata, "RFC7519-4.1.3"),
		},
		redirect: { withoutDuplicates: true },
	});
}

/**
 * upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectWithoutExpFails.java
 * (AbstractFAPI2SPFinalPARExpectingAuthorizationEndpointPlaceholderOrCallback)
 */
export async function fapi2EnsureRequestObjectWithoutExpFails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		requestObject: { omitExp: "NOT adding exp to request object" },
		processParResponse: expectingParErrorOrCallback((res) =>
			soft(() => par.ensurePARInvalidRequestObjectError(res, "JAR-6.2", "PAR-2.3")),
		),
		createPlaceholder: () => authz.expectRequestObjectMissingExpClaimErrorPage("FAPI2-MS-ID1-5.3.1-4"),
	});
	if (response == null) {
		return;
	}
	await verifyAuthorizationResponse(fapi, client, request, response, {
		onAuthorizationCallbackResponse: (res) => {
			/* If we get an error back from the authorization server:
			 * - It must be a 'invalid_request_object', 'invalid_request' or 'access_denied' error
			 * - It must have the correct state we supplied
			 */
			soft(() => authz.checkStateInAuthorizationResponse(request, res));
			soft(() => authz.ensureErrorFromAuthorizationEndpointResponse(res, "OIDCC-3.1.2.6"));
			soft(
				() => authz.checkForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint(res, {}, "OIDCC-3.1.2.6"),
				"warning",
			);
			// isPar
			soft(() =>
				authz.ensureInvalidRequestInvalidRequestUriOrAccessDeniedError(res, "OIDCC-3.1.2.6", "RFC6749-4.2.2.1"),
			);
			return null;
		},
	});
}

/**
 * upstream: fapi2spfinal/FAPI2SPFinalEnsureExpiredRequestObjectFails.java
 * (AbstractFAPI2SPFinalPARExpectingAuthorizationEndpointPlaceholderOrCallback)
 */
export async function fapi2EnsureExpiredRequestObjectFails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		requestObject: { exp: (claims) => requestObject.addExpiredExpToRequestObject(claims, "RFC7519-4.1.4") },
		processParResponse: expectingParErrorOrCallback((res) =>
			soft(() => par.ensurePARInvalidRequestObjectError(res, "JAR-6.2", "PAR-2.3")),
		),
		createPlaceholder: () => authz.expectExpiredRequestObjectClaimErrorPage("RFC7519-4.1.4"),
	});
	if (response == null) {
		return;
	}
	// isPar: allowPlainErrorResponseForJarm
	await verifyAuthorizationResponse(fapi, client, request, response, {
		allowPlainErrorResponseForJarm: true,
		onAuthorizationCallbackResponse: (res) => {
			/* If we get an error back from the authorization server:
			 * - It must be a 'invalid_request_object' error
			 * - It must have the correct state we supplied
			 */
			soft(() => authz.checkStateInAuthorizationResponse(request, res));
			soft(() => authz.ensureErrorFromAuthorizationEndpointResponse(res, "OIDCC-3.1.2.6"));
			soft(
				() => authz.checkForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint(res, {}, "OIDCC-3.1.2.6"),
				"warning",
			);
			soft(() => authz.ensureInvalidRequestObjectError(res, "OIDCC-3.1.2.6"));
			return null;
		},
	});
}

// ---- the modules that expect a rejection at the PAR endpoint, an error page or an error in the callback ----

/**
 * The checks on an error returned to the redirect_uri: the state, the error, no unexpected parameters, then the
 * module's check of the error value; the module ends (null).
 *
 * upstream: the onAuthorizationCallbackResponse of the modules on
 * AbstractFAPI2SPFinalPARExpectingAuthorizationEndpointPlaceholderOrCallback
 */
function expectAuthorizationErrorResponse(
	request: Fapi2AuthorizationRequest,
	res: authz.AuthorizationResponse,
	checkError: (res: authz.AuthorizationResponse) => void,
): null {
	/* If we get an error back from the authorization server:
	 * - It must be the error the module expects
	 * - It must have the correct state we supplied
	 */
	soft(() => authz.checkStateInAuthorizationResponse(request, res));
	soft(() => authz.ensureErrorFromAuthorizationEndpointResponse(res, "OIDCC-3.1.2.6"));
	soft(
		() => authz.checkForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint(res, {}, "OIDCC-3.1.2.6"),
		"warning",
	);
	soft(() => checkError(res));
	return null;
}

/** What a module on AbstractFAPI2SPFinalPARExpectingAuthorizationEndpointPlaceholderOrCallback overrides */
interface PlaceholderOrCallbackModule {
	/** makeCreateAuthorizationRequestSteps / makeCreateAuthorizationRequestObjectSteps / createAuthorizationRequestObject / isSignedRequest */
	flow?: AuthorizationFlowOptions;
	createPlaceholder: () => string;
	/** the check of the PAR endpoint's error response (callAndContinueOnFailure, FAILURE) */
	processParErrorResponse: (res: par.ParResponse) => void;
	/** the check of the error returned to the redirect_uri, after the state / error / unexpected parameters checks */
	checkAuthorizationError: (res: authz.AuthorizationResponse) => void;
	allowPlainErrorResponseForJarm?: boolean;
}

/**
 * The server may reject the request at the PAR endpoint (the module ends there), with an error page (the browser
 * automation screenshots it into the placeholder) or with an error returned to the redirect_uri.
 *
 * upstream: AbstractFAPI2SPFinalPARExpectingAuthorizationEndpointPlaceholderOrCallback (processParResponse,
 * performRedirectAndWaitForPlaceholdersOrCallback, the module's onAuthorizationCallbackResponse)
 */
async function expectParErrorOrAuthorizationError(
	op: Fapi2Op,
	client: Fapi2Client,
	module: PlaceholderOrCallbackModule,
): Promise<void> {
	const { request, response } = await performAuthorizationFlow(op, client, op.redirectUri, {
		...module.flow,
		processParResponse: expectingParErrorOrCallback((res) => soft(() => module.processParErrorResponse(res))),
		createPlaceholder: module.createPlaceholder,
	});
	if (response == null) {
		// the PAR endpoint rejected the request, or the OP showed an error page (its screenshot is in the log)
		return;
	}
	await verifyAuthorizationResponse(op, client, request, response, {
		allowPlainErrorResponseForJarm: module.allowPlainErrorResponseForJarm,
		onAuthorizationCallbackResponse: (res) =>
			expectAuthorizationErrorResponse(request, res, module.checkAuthorizationError),
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectWithoutRedirectUriFails.java */
export async function fapi2EnsureRequestObjectWithoutRedirectUriFails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	await expectParErrorOrAuthorizationError(fapi, client, {
		flow: {
			requestObject: { beforeSign: (claims) => requestObject.removeRedirectUriFromRequestObject(claims) },
			// with an unsigned request the claims are the pushed form parameters: the PAR request loses its redirect_uri
			beforePar: (request) => requestObject.removeRedirectUriFromRequestObject(request.requestObjectClaims),
		},
		createPlaceholder: () => authz.expectRequestObjectMissingRedirectUriErrorPage("FAPI2-MS-ID1-5.3.2-1"),
		processParErrorResponse: (res) => par.ensurePARInvalidRequestOrInvalidRequestObjectError(res, "JAR-6.2"),
		checkAuthorizationError: (res) =>
			authz.checkErrorFromAuthorizationEndpointErrorInvalidRequestOrInvalidRequestObject(res, "OIDCC-3.1.2.6"),
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectWithoutNbfFails.java */
export async function fapi2EnsureRequestObjectWithoutNbfFails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	await expectParErrorOrAuthorizationError(fapi, client, {
		flow: { requestObject: { omitNbf: "NOT adding nbf to request object" } },
		createPlaceholder: () => authz.expectRequestObjectMissingNbfClaimErrorPage("FAPI2-MS-ID1-5.3.1-3"),
		processParErrorResponse: (res) => par.ensurePARInvalidRequestObjectError(res, "JAR-6.3", "PAR-2.1-3"),
		// isPar
		checkAuthorizationError: (res) =>
			authz.ensureInvalidRequestInvalidRequestUriOrAccessDeniedError(res, "OIDCC-3.1.2.6", "RFC6749-4.2.2.1"),
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectWithBadAudFails.java */
export async function fapi2EnsureRequestObjectWithBadAudFails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	await expectParErrorOrAuthorizationError(fapi, client, {
		flow: {
			requestObject: { aud: (claims) => requestObject.addBadAudToRequestObject(claims, "OIDCC-6.1", "RFC7519-4.1.3") },
		},
		createPlaceholder: () => authz.expectRequestObjectWithBadAudClaimErrorPage("OIDCC-6.1", "RFC7519-4.1.3"),
		processParErrorResponse: (res) => par.ensurePARInvalidRequestObjectError(res, "JAR-6.2", "PAR-2.3"),
		// isPar
		checkAuthorizationError: (res) => authz.ensureInvalidRequestUriError(res, "JAR-4"),
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectWithExpOver60Fails.java */
export async function fapi2EnsureRequestObjectWithExpOver60Fails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	await expectParErrorOrAuthorizationError(fapi, client, {
		flow: {
			requestObject: {
				exp: (claims) =>
					requestObject.addExpValueIs70MinutesInFutureToRequestObject(claims, "OIDCC-6.1", "RFC7519-4.1.4"),
			},
		},
		createPlaceholder: () => authz.expectRequestObjectWithExpOver60ClaimErrorPage("FAPI2-MS-ID1-5.3.1-4"),
		processParErrorResponse: (res) => par.ensurePARInvalidRequestObjectError(res, "JAR-6.3", "PAR-2.1-3"),
		// isPar
		checkAuthorizationError: (res) => authz.ensureInvalidRequestUriError(res, "JAR-4"),
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectWithNbfOver60Fails.java */
export async function fapi2EnsureRequestObjectWithNbfOver60Fails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	await expectParErrorOrAuthorizationError(fapi, client, {
		flow: {
			requestObject: {
				nbf: (claims) => requestObject.addNbfValueIs70MinutesInPastToRequestObject(claims, "FAPI2-MS-ID1-5.3.1-3"),
			},
		},
		createPlaceholder: () => authz.expectRequestObjectWithNbfOver60ClaimErrorPage("OIDCC-6.1", "RFC7519-4.1.5"),
		processParErrorResponse: (res) => par.ensurePARInvalidRequestObjectError(res, "JAR-6.3", "PAR-2.1-3"),
		// isPar
		checkAuthorizationError: (res) => authz.ensureInvalidRequestUriError(res, "JAR-4"),
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureSignedRequestObjectWithRS256Fails.java */
export async function fapi2EnsureSignedRequestObjectWithRS256Fails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	// onConfigure: If ES256 keys are supplied, the test module should probably just immediately exit successfully
	// We don't need to check null for jwks and keys because it was checked the steps before
	// We get first key to compare with PS256 because we use it to sign request_object or client_assertion
	const alg = algFromClientJwks(client);
	if (alg !== "PS256") {
		// FAPI only allows ES256 and PS256
		// This throws an exception: the test will stop here
		skipTest(
			`This test requires RSA keys to be performed, the alg in client configuration is '${alg}' so this test is being skipped. If your server does not support PS256 then this will not prevent you certifying.`,
		);
	}
	await expectParErrorOrAuthorizationError(fapi, client, {
		flow: {
			// a copy of the jwks, so the client assertions are still signed with the original one
			createAuthorizationRequestObject: async (request) => {
				const rs256Client = { ...client, keys: structuredClone(client.keys) };
				token.changeClientJwksAlgToRS256(rs256Client, "FAPI2-SP-FINAL-5.4");
				await fapi2.createAuthorizationRequestObject(fapi, rs256Client, request);
			},
		},
		createPlaceholder: () => authz.expectSignedRS256RequestObjectErrorPage("FAPI2-SP-FINAL-5.4"),
		processParErrorResponse: (res) => par.ensurePARInvalidRequestObjectError(res, "JAR-6.2"),
		checkAuthorizationError: (res) => authz.ensureInvalidRequestObjectError(res, "OIDCC-3.1.2.6"),
		// isPar
		allowPlainErrorResponseForJarm: true,
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectSignatureAlgorithmIsNotNone.java */
export async function fapi2EnsureRequestObjectSignatureAlgorithmIsNotNone({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	await expectParErrorOrAuthorizationError(fapi, client, {
		flow: {
			requestObject: { sign: async (claims) => requestObject.serializeRequestObjectWithNullAlgorithm(claims) },
			redirect: { exposeState: true },
		},
		createPlaceholder: () => authz.expectRequestObjectUnverifiableErrorPage("FAPI2-MS-ID1-5.4.2-2"),
		processParErrorResponse: (res) => par.ensurePARInvalidRequestObjectError(res, "JAR-6.2"),
		checkAuthorizationError: (res) => authz.ensureInvalidRequestObjectError(res, "OIDCC-3.1.2.6"),
		// isPar
		allowPlainErrorResponseForJarm: true,
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectWithInvalidSignatureFails.java */
export async function fapi2EnsureRequestObjectWithInvalidSignatureFails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	await expectParErrorOrAuthorizationError(fapi, client, {
		flow: { requestObject: { afterSign: (jwt) => requestObject.invalidateRequestObjectSignature(jwt) } },
		createPlaceholder: () => authz.expectRequestObjectInvalidSignatureErrorPage(),
		processParErrorResponse: (res) => par.ensurePARInvalidRequestObjectError(res, "JAR-6.2"),
		checkAuthorizationError: (res) => authz.ensureInvalidRequestObjectError(res, "OIDCC-3.1.2.6"),
		// isPar
		allowPlainErrorResponseForJarm: true,
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureMatchingKeyInAuthorizationRequest.java */
export async function fapi2EnsureMatchingKeyInAuthorizationRequest({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const client2 = await fapi2.configureSecondClient(fapi, client);
	fapi2.setupResourceEndpoint(fapi);
	await expectParErrorOrAuthorizationError(fapi, client, {
		flow: {
			// Switch to client 2 JWKs
			createAuthorizationRequestObject: (request) =>
				block("Sign request object containing client_id for client 1 using JWK for client 2", () =>
					fapi2.createAuthorizationRequestObject(fapi, { ...client, keys: client2.keys }, request),
				),
			redirect: { exposeState: true },
		},
		createPlaceholder: () => authz.expectRequestObjectUnverifiableErrorPage("FAPI2-MS-ID1-5.3.1-1", "OIDCC-6.3.2"),
		processParErrorResponse: (res) => par.ensurePARInvalidRequestOrInvalidRequestObjectError(res, "JAR-6.2"),
		checkAuthorizationError: (res) => authz.ensureInvalidRequestObjectError(res, "OIDCC-3.1.2.6"),
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureUnsignedRequestAtParEndpointFails.java */
export async function fapi2EnsureUnsignedRequestAtParEndpointFails({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	await expectParErrorOrAuthorizationError(fapi, client, {
		// onConfigure: isSignedRequest = false
		flow: { signedRequest: false },
		createPlaceholder: () => authz.expectAuthorizationRequestWithoutRequestObjectErrorPage("FAPI2-MS-ID1-5.3.2-1"),
		processParErrorResponse: (res) => par.ensurePARInvalidRequestError(res, "PAR-2.3"),
		checkAuthorizationError: (res) =>
			authz.checkErrorFromAuthorizationEndpointErrorInvalidRequestOrInvalidRequestObjectOrInvalidRequestUri(
				res,
				"OIDCC-3.1.2.6",
			),
	});
}

/**
 * upstream: fapi2spfinal/FAPI2SPFinalPAREnsurePlainPKCERejected.java
 * (AbstractFAPI2SPFinalPARExpectingAuthorizationEndpointPlaceholderOrCallback)
 */
export async function fapi2PAREnsurePlainPKCERejected({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		request: {
			// ideally we'd replace the CreateS256CodeChallenge call instead, but
			// .replace() doesn't currently work for sequences-within-sequences
			steps: (params, { codeVerifier }) => {
				const { codeChallenge, codeChallengeMethod } = authz.createPlainCodeChallenge(codeVerifier ?? "");
				authz.addCodeChallengeToAuthorizationEndpointRequest(params, codeChallenge, codeChallengeMethod);
			},
		},
		processParResponse: expectingParErrorOrCallback((res) =>
			soft(() => par.ensurePARInvalidRequestError(res, "RFC7636-4.4.1")),
		),
		createPlaceholder: () => authz.expectPlainPkceErrorPage("FAPI2-SP-FINAL-5.3.2.2-5"),
	});
	if (response == null) {
		return;
	}
	await verifyAuthorizationResponse(fapi, client, request, response, {
		onAuthorizationCallbackResponse: (res) => {
			soft(() => authz.ensureInvalidRequestError(res, "RFC7636-4.4.1"));
			return null;
		},
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectWithNbf8SecondsInTheFutureIsAccepted.java */
export async function fapi2EnsureRequestObjectWithNbf8SecondsInTheFutureIsAccepted({
	fapi,
}: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		requestObject: {
			nbf: (claims) => requestObject.addNbfValueIs8SecondsInFutureToRequestObject(claims, "FAPI2-SP-FINAL-5.3.2.1"),
		},
		processParResponse: (res) => {
			// if response code is not 201 then skip test
			if (res.status !== 201) {
				soft(() => par.checkPAREndpointResponse201WithNoError(res, "PAR-2.2", "PAR-2.3"), "warning");
				// UPSTREAM: logged under the test id rather than the test name
				fapi.log.log(fapi.testId, "PAR endpoint doesn't seem to support clock skew, finishing test prematurely.");
				return null;
			}
			return fapi2.processParResponse(res);
		},
	});
	if (response == null) {
		return;
	}
	const code = (await verifyAuthorizationResponse(fapi, client, request, response)) as string;
	await performPostAuthorizationFlow(fapi, client, request, code, resource);
}

// ---- the request_uri modules ----

/**
 * upstream: fapi2spfinal/FAPI2SPFinalPAREnsureServerAcceptsReusedRequestUriBeforeAuthenticationCompletion.java
 */
export async function fapi2PAREnsureServerAcceptsReusedRequestUriBeforeAuthenticationCompletion({
	fapi,
}: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		performRedirect: async (req) => {
			// Initial visit to the authorization endpoint. The user should take no action (the browser automation of
			// this module only waits for the login page). Upstream polls the visited urls for up to 120 seconds; here
			// the visit resolves once the automation ran on the page.
			await fapi.browser.visit(req.url);
			if (!fapi.browser.visited.includes(req.url)) {
				throw new Error(
					"The initial authorization server login page was not visited within the 120 seconds timeout period.",
				);
			}
			// Proceed with the regular authorization flow, revisiting the authorization endpoint and logging in.
			return block("Make second request to authorization endpoint", () =>
				authz.authorizeExpectingErrorPageOrRedirect(fapi, req, authz.expectLoginPage()),
			);
		},
	});
	if (response == null) {
		// the OP showed an error page instead of the login page (its screenshot is in the log)
		return;
	}
	// The user must not authenticate until the second visit to the login page: the callback is only awaited on it
	const code = await verifyAuthorizationResponse(fapi, client, request, response, {
		onAuthorizationCallbackResponse: (res) => {
			if (!Object.hasOwn(res.params, "error")) {
				return fapi2.onAuthorizationCallbackResponse(fapi, request, res);
			}
			// If we get an error back from the authorization server:
			// - It must be a 'invalid_request_uri' error
			// - It must have the correct state we supplied
			soft(() => authz.warningAboutRequestUriError("FAPI2-SP-FINAL-5.3.2.2"), "warning");
			soft(() => authz.checkStateInAuthorizationResponse(request, res));
			soft(() => authz.ensureErrorFromAuthorizationEndpointResponse(res, "OIDCC-3.1.2.6"));
			soft(
				() => authz.checkForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint(res, {}, "OIDCC-3.1.2.6"),
				"warning",
			);
			soft(() => authz.ensureInvalidRequestUriError(res, "OIDCC-3.3.2.6"));
			return null;
		},
	});
	if (code != null) {
		await performPostAuthorizationFlow(fapi, client, request, code, resource);
	}
}

/** upstream: fapi2spfinal/FAPI2SPFinalPARAttemptReuseRequestUri.java */
export async function fapi2PARAttemptReuseRequestUri({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	const { request, requestUri, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri);
	// first authentication is a normal successful one
	const code = (await verifyAuthorizationResponse(
		fapi,
		client,
		request,
		response as authz.AuthorizationResponse,
	)) as string;
	await performPostAuthorizationFlow(fapi, client, request, code, resource);

	//PAR-7.3 : An attacker could replay a request URI captured from a legitimate authorization request.
	// In order to cope with such attacks, the AS SHOULD make the request URIs one-time use.
	const second = await block(
		"Attempting reuse of request_uri and testing if Authorization server returns error in callback",
		() => {
			fapi2.buildPARRedirect(fapi, request, requestUri as string);
			// createPlaceholder (upstream ends the block there: the redirect's entries carry no block id)
			return authz.authorizeExpectingErrorPageOrRedirect(
				fapi,
				request,
				authz.expectInvalidRequestUriErrorPage("PAR-7.3", "PAR-4", "PAR-2.2"),
			);
		},
	);
	if (second == null) {
		return;
	}
	const secondCode = await verifyAuthorizationResponse(fapi, client, request, second, {
		allowPlainErrorResponseForJarm: true,
		onAuthorizationCallbackResponse: (res) => {
			if (Object.hasOwn(res.params, "error")) {
				soft(() => authz.ensureInvalidRequestUriError(res, "PAR-2.2", "JAR-7"));
				return null;
			}
			// second authentication "should" return an error, but only a should so warn but otherwise expect a
			// successful response
			soft(() => authz.ensureErrorFromAuthorizationEndpointResponse(res, "PAR-7.3"), "warning");
			return fapi2.onAuthorizationCallbackResponse(fapi, request, res);
		},
	});
	if (secondCode != null) {
		// the server does not implement the 'should': the successful response when reusing the request_uri is
		// verified (a warning was logged) and the test ends
		await performPostAuthorizationFlow(fapi, client, request, secondCode, resource);
	}
}

/** upstream: FAPI2SPFinalPARAttemptToUseExpiredRequestUri.waitForExpiresIn */
async function waitForExpiresIn(parResponse: par.ParResponse): Promise<void> {
	//expires_in : A JSON number that represents the lifetime of the request URI in seconds.
	// The request URI lifetime is at the discretion of the AS.
	const expiresIn = parResponse.json?.["expires_in"];
	const seconds = typeof expiresIn === "number" ? Math.trunc(expiresIn) : null;
	if (seconds != null && seconds > 30 * 60) {
		skipTest("The expires in value is longer than 30 minutes so is too long for the suite to wait for it to expire.");
	}
	await waitForExpiry(seconds);
}

/** upstream: fapi2spfinal/FAPI2SPFinalPARAttemptToUseExpiredRequestUri.java */
export async function fapi2PARAttemptToUseExpiredRequestUri({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	//PAR-2.2.0 : If the verification is successful, the server MUST generate a request URI and return a
	// JSON response that contains request_uri and expires_in members at the top level with 201 Created
	// HTTP response code.
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		redirectBlock:
			"Attempting use of request_uri after expiry and testing if Authorization server returns error in callback",
		//wait for expiry of request_uri
		beforeRedirect: (_request, parResponse) => waitForExpiresIn(parResponse),
		redirectRequirements: [],
		createPlaceholder: () => authz.expectInvalidRequestUriErrorPage("PAR-2.2"),
	});
	if (response == null) {
		return;
	}
	// onConfigure: allowPlainErrorResponseForJarm
	await verifyAuthorizationResponse(fapi, client, request, response, {
		allowPlainErrorResponseForJarm: true,
		onAuthorizationCallbackResponse: (res) => {
			// verifyError
			soft(() => authz.ensureInvalidRequestUriError(res, "PAR-2.2"));
			return null;
		},
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalPAREnsureRequestUriIsBoundToClient.java */
export async function fapi2PAREnsureRequestUriIsBoundToClient({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const client2 = await fapi2.configureSecondClient(fapi, client);
	fapi2.setupResourceEndpoint(fapi);
	//PAR-2.2.1 : The request_uri MUST be bound to the client that posted the authorization request.
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		redirectBlock:
			"Attempting to send client2's clientId with request_uri to AS and expect it returns error in callback",
		// switchToSecondClient
		beforeRedirect: (req) => authz.addClientIdToAuthorizationEndpointRequest(req.params, client2.client, "PAR-4"),
		redirectRequirements: [],
		createPlaceholder: () => authz.expectInvalidRequestUriErrorPage("PAR-3-3"),
	});
	if (response == null) {
		return;
	}
	// onConfigure: allowPlainErrorResponseForJarm; the second client is in use when the callback is processed
	await verifyAuthorizationResponse(fapi, client2, request, response, {
		allowPlainErrorResponseForJarm: true,
		onAuthorizationCallbackResponse: (res) => {
			// verifyError
			soft(() => authz.ensureInvalidRequestInvalidRequestObjectOrInvalidRequestUriError(res, "PAR-3-3"));
			return null;
		},
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalPARRejectRequestUriInParAuthorizationFormParams.java */
export async function fapi2PARRejectRequestUriInParAuthorizationFormParams({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	const request = await createAuthorizationRequest(fapi, client, fapi.redirectUri);
	//PAR-2.1 : The request_uri authorization request parameter MUST NOT be provided in this case
	await block("Make request to PAR endpoint", async () => {
		const parRequest = fapi2.buildPAREndpointRequest(request);
		par.addBadRequestUriToRequestParameters(parRequest);
		const res = await fapi2.callParEndpointAndStopOnFailure(fapi, client, parRequest);
		soft(() => par.ensurePARInvalidRequestOrInvalidRequestObjectOrRequestUriNotSupportedError(res, "PAR-2.1-2"));
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalPARRejectInvalidHttpVerb.java */
export async function fapi2PARRejectInvalidHttpVerb({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	const request = await createAuthorizationRequest(fapi, client, fapi.redirectUri);
	//PAR-2.3.3 : If the request did not use POST, the authorization server shall return 405 Method Not Allowed HTTP error response.
	await block("Make request to PAR endpoint", async () => {
		const parRequest = fapi2.buildPAREndpointRequest(request);
		const res = await fapi2.callParEndpointAndStopOnFailure(fapi, client, parRequest, { method: "PUT" });
		soft(() => par.ensureParHTTPError(res, "PAR-2.3"));
	});
}

/** upstream: fapi2spfinal/FAPI2SPFinalPARRejectRequestUriInParAuthorizationRequest.java */
export async function fapi2PARRejectRequestUriInParAuthorizationRequest({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	//PAR-2.1 : The request_uri authorization request parameter MUST NOT be provided in this case
	const request = await createAuthorizationRequest(fapi, client, fapi.redirectUri, {
		// butFirst: before the request parameters become the request object's claims
		request: { steps: (params) => authz.addBadRequestUriToAuthorizationRequest(params, "PAR-2") },
	});
	await block("Make request to PAR endpoint", async () => {
		const parRequest = fapi2.buildPAREndpointRequest(request);
		const res = await fapi2.callParEndpointAndStopOnFailure(fapi, client, parRequest);
		// this might be too strict, the spec mentions this error but doesn't require servers to use it
		// the only firm requirement is for the http status code to indicate failure
		soft(() => par.ensurePARInvalidRequestObjectError(res, "JAR-6.2", "PAR-2.1"));
	});
}

// ---- the PKCE token endpoint modules ----

/**
 * upstream: FAPI2SPFinalPAREnsurePKCECodeVerifierRequired / FAPI2SPFinalPARIncorrectPKCECodeVerifierRejected
 * .processTokenEndpointResponse
 */
function expectInvalidGrantFromTokenEndpoint(res: token.TokenResponse): void {
	/* expect an 'invalid_grant' error */
	soft(() => token.checkTokenEndpointHttpStatus400(res, "RFC6749-5.2"));
	soft(() => token.checkTokenEndpointReturnedJsonContentType(res, "OIDCC-3.1.3.4"));
	soft(() => token.checkErrorFromTokenEndpointResponseErrorInvalidGrant(res, "RFC7636-4.6", "RFC6749-5.2"));
	soft(() => token.validateErrorFromTokenEndpointResponseError(res, "RFC6749-5.2"));
	soft(() => token.checkErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB(res, "RFC6749-5.2"), "warning");
	soft(() => token.validateErrorDescriptionFromTokenEndpointResponseError(res, "RFC6749-5.2"));
	soft(() => token.validateErrorUriFromTokenEndpointResponseError(res, "RFC6749-5.2"));
}

/**
 * The flow up to the token request, which is sent with the module's PKCE code_verifier (none, or another one) and
 * must be rejected with invalid_grant.
 *
 * upstream: AbstractFAPI2SPFinalPerformTokenEndpoint (performPostAuthorizationFlow: createAuthorizationCodeRequest
 * with the module's addPkceCodeVerifier, exchangeAuthorizationCode)
 */
async function performTokenEndpointWithCodeVerifier(
	op: Fapi2Op,
	client: Fapi2Client,
	addPkceCodeVerifier: (req: token.TokenRequest) => void,
): Promise<void> {
	const { request, response } = await performAuthorizationFlow(op, client, op.redirectUri);
	const code = (await verifyAuthorizationResponse(
		op,
		client,
		request,
		response as authz.AuthorizationResponse,
	)) as string;
	const tokenResponse = await block("Call token endpoint", async () => {
		const req = token.createTokenEndpointRequestForAuthorizationCodeGrant(code, request.redirectUri);
		addPkceCodeVerifier(req);
		// plain_fapi: no token endpoint profile headers
		return fapi2.callSenderConstrainedTokenEndpoint(op, client, req);
	});
	await block("Verify token endpoint response", () => expectInvalidGrantFromTokenEndpoint(tokenResponse));
}

/** upstream: fapi2spfinal/FAPI2SPFinalPAREnsurePKCECodeVerifierRequired.java (AbstractFAPI2SPFinalPerformTokenEndpoint) */
export async function fapi2PAREnsurePKCECodeVerifierRequired({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	// addPkceCodeVerifier: nothing
	await performTokenEndpointWithCodeVerifier(fapi, client, () => {});
}

/** upstream: fapi2spfinal/FAPI2SPFinalPARIncorrectPKCECodeVerifierRejected.java (AbstractFAPI2SPFinalPerformTokenEndpoint) */
export async function fapi2PARIncorrectPKCECodeVerifierRejected({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	fapi2.setupResourceEndpoint(fapi);
	await performTokenEndpointWithCodeVerifier(fapi, client, (req) => {
		// create a new, different code verified
		const verifier = authz.createRandomCodeVerifier("RFC7636-4.1");
		token.addCodeVerifierToTokenEndpointRequest(req, verifier, "RFC7636-4.5", "FAPI2-SP-FINAL-5.3.3.2-3");
	});
}

// ---- the parameters outside the request object ----

/**
 * The module's callback checks: a successful response without state (the code), or the permitted errors.
 *
 * upstream: fapi2spfinal/AbstractFAPI2SPFinalEnsureRequestObjectWithoutState.onAuthorizationCallbackResponse
 */
function ensureRequestObjectWithoutStateCallback(
	request: Fapi2AuthorizationRequest,
	res: authz.AuthorizationResponse,
): string | null {
	if (!Object.hasOwn(res.params, "error")) {
		authz.checkMatchingCallbackParameters(request, res);
		authz.checkIfAuthorizationEndpointError(res);
		soft(() => authz.verifyNoStateInAuthorizationResponse(res));
		const code = authz.extractAuthorizationCodeFromAuthorizationResponse(res);
		soft(() => authz.ensureMinimumAuthorizationCodeLength(code, "RFC6749-10.10", "RFC6819-5.1.4.2-2"));
		soft(() => authz.ensureMinimumAuthorizationCodeEntropy(code, "RFC6749-10.10", "RFC6819-5.1.4.2-2"));
		return code;
	}
	/* If we get an error back from the authorization server:
	 * - It must be a 'invalid_request_object', 'invalid_request' or 'access_denied' error
	 * - It must have the correct state we supplied
	 */
	// state can be absented if authorization request did not send state in the request object
	if (res.params["state"] == null) {
		skipped("CheckStateInAuthorizationResponse", { element: ["authorization_endpoint_response", "state"] });
	} else {
		soft(() => authz.checkStateInAuthorizationResponse(request, res));
	}
	soft(() => authz.ensureErrorFromAuthorizationEndpointResponse(res, "OIDCC-3.1.2.6"));
	soft(
		() => authz.checkForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint(res, {}, "OIDCC-3.1.2.6"),
		"warning",
	);
	soft(() =>
		authz.ensureInvalidRequestInvalidRequestObjectInvalidRequestUriOrAccessDeniedError(
			res,
			"OIDCC-3.1.2.6",
			"RFC6749-4.2.2.1",
		),
	);
	return null;
}

/**
 * upstream: fapi2spfinal/FAPI2SPFinalStateOnlyOutsideRequestObjectNotUsed.java
 * (AbstractFAPI2SPFinalEnsureRequestObjectWithoutState)
 */
export async function fapi2StateOnlyOutsideRequestObjectNotUsed({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	const { request, response } = await performAuthorizationFlow(fapi, client, fapi.redirectUri, {
		request: { omit: { state: "NOT adding state to request object" } },
		// Note: BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint and
		// BuildRequestObjectByValueRedirectToAuthorizationEndpoint include as URL
		// parameters values in "authorization_endpoint_request" which differ or are
		// missing from the request object. Here a state is added as a parameter.
		beforeRedirect: (req) => authz.addStateToAuthorizationEndpointRequest(req.params, req.state as string),
		createPlaceholder: () => authz.expectRequestObjectMissingStateErrorPage("RFC6749-4.1.1"),
	});
	if (response == null) {
		return;
	}
	const code = await verifyAuthorizationResponse(fapi, client, request, response, {
		onAuthorizationCallbackResponse: (res) => ensureRequestObjectWithoutStateCallback(request, res),
	});
	if (code != null) {
		await performPostAuthorizationFlow(fapi, client, request, code, resource);
	}
}

/**
 * The flow of the modules that send a parameter outside the request object differing from the one inside: the OP
 * may return invalid_request, show an error page, or authenticate with the value inside.
 *
 * upstream: FAPI2SPFinalEnsureDifferentNonceInsideAndOutsideRequestObject /
 * FAPI2SPFinalEnsureDifferentStateInsideAndOutsideRequestObject (AbstractFAPI2SPFinalExpectingAuthorizationEndpointPlaceholderOrCallback)
 */
async function performFlowWithDifferentParameterOutsideRequestObject(
	op: Fapi2Op,
	client: Fapi2Client,
	resource: Resource,
	addIncorrectParameter: (params: Record<string, unknown>) => void,
	createPlaceholder: () => string,
): Promise<void> {
	const { request, response } = await performAuthorizationFlow(op, client, op.redirectUri, {
		// Note: BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint and
		// BuildRequestObjectByValueRedirectToAuthorizationEndpoint include as URL
		// parameters values in "authorization_endpoint_request" which differ or are
		// missing from the request object. Here, an incorrect value is added as a parameter.
		beforeRedirect: (req) => addIncorrectParameter(req.params),
		createPlaceholder,
	});
	if (response == null) {
		return;
	}
	const code = await verifyAuthorizationResponse(op, client, request, response, {
		onAuthorizationCallbackResponse: (res) => {
			if (!Object.hasOwn(res.params, "error")) {
				return fapi2.onAuthorizationCallbackResponse(op, request, res);
			}
			/* If we get an error back from the authorization server:
			 * - It must be a 'invalid_request' error
			 * - It must have the correct state we supplied
			 */
			soft(() => authz.checkStateInAuthorizationResponse(request, res));
			soft(() => authz.ensureErrorFromAuthorizationEndpointResponse(res, "OIDCC-3.1.2.6"));
			soft(
				() => authz.checkForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint(res, {}, "OIDCC-3.1.2.6"),
				"warning",
			);
			soft(() => authz.ensureInvalidRequestError(res, "OIDCC-3.3.2.6"));
			return null;
		},
	});
	if (code != null) {
		await performPostAuthorizationFlow(op, client, request, code, resource);
	}
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureDifferentNonceInsideAndOutsideRequestObject.java */
export async function fapi2EnsureDifferentNonceInsideAndOutsideRequestObject({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	await performFlowWithDifferentParameterOutsideRequestObject(
		fapi,
		client,
		resource,
		authz.addIncorrectNonceToAuthorizationEndpointRequest,
		() => authz.expectRequestDifferentNonceInsideAndOutsideErrorPage("OIDCC-6.1"),
	);
}

/** upstream: fapi2spfinal/FAPI2SPFinalEnsureDifferentStateInsideAndOutsideRequestObject.java */
export async function fapi2EnsureDifferentStateInsideAndOutsideRequestObject({ fapi }: Fapi2Fixtures): Promise<void> {
	const client = fapi2.configureClient(fapi);
	const resource = fapi2.setupResourceEndpoint(fapi);
	await performFlowWithDifferentParameterOutsideRequestObject(
		fapi,
		client,
		resource,
		authz.addIncorrectStateToAuthorizationEndpointRequest,
		() => authz.expectRequestDifferentStateInsideAndOutsideErrorPage("FAPI2-MS-ID1-5.3.2-1"),
	);
}

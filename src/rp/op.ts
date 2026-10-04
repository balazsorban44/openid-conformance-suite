/**
 * The emulated OpenID Provider an RP test runs against (upstream openid/client/AbstractOIDCCClientTest.java): its
 * endpoints (discovery, jwks, registration, authorization, token, userinfo) served on the test's own server, the
 * checks upstream runs on every request the RP sends, and the events a test awaits to follow the flow.
 *
 *   const op = await startEmulatedOp(server, { testName, variant, config }, {
 *     idTokenClaims: (claims) => idToken.addInvalidAudValueToIdToken(claims, "OIDCC-3.1.3.7", "OIDCC-2"),
 *   });
 *   ... start the RP (rp.driveClient()) ...
 *   const { authorization } = await op.expect("authorization");   // the RP's authorization request was answered
 *   await op.expect("token");
 *   const userinfo = await op.waitFor("userinfo", 5);              // null: the RP did not call userinfo
 *
 * A module's differences from the default flow are {@link EmulatedOpOptions} (upstream's overridable methods as
 * plain options / callbacks). Requests are handled one at a time (upstream's test lock); a check that fails while
 * handling a request ends the test: every pending and later expect()/waitFor() rejects with it.
 */
import { extractClientNameFromStoredConfig, storeOriginalClientConfiguration } from "../op/registration.ts";
import { block, ConditionFailed, logModule, soft } from "../suite/conditions.ts";
import type { TestConfig } from "../suite/config.ts";
import type { Jwks, ParsedJwt } from "../suite/jose.ts";
import { currentContext, escapeHtml, withContext } from "../suite/log.ts";
import { htmlResponse, type IncomingRequest, type TestServer } from "../suite/server.ts";
import {
	formPostResponsePage,
	handleAuthorizationRequest,
	type AuthorizationParams,
	type AuthorizationState,
} from "./authorization.ts";
import {
	discoveryResponse,
	ensureServerConfigurationHasRequiredOidcMetadata,
	oidccGenerateServerConfiguration,
	setTokenEndpointAuthMethodsSupportedOnly,
	type ServerMetadata,
} from "./discovery.ts";
import { oidccExtractServerSigningAlg, type IdTokenClaims } from "./id-token.ts";
import { configureServerJwks, jwksResponse, type ServerKeys } from "./jwks.ts";
import {
	handleEndSessionRequest,
	handleFrontChannelLogoutCallback,
	type EndSessionEvent,
	type LogoutOptions,
} from "./logout.ts";
import {
	handleRegistrationRequest,
	oidccGetStaticClientConfigurationForRPTests,
	processAndValidateClientJwks,
	setClientIdTokenSignedResponseAlgToServerSigningAlg,
	validateClientMetadata,
	type RpClient,
} from "./registration.ts";
import { configureRequestObjectSupport } from "./request-object.ts";
import { handleTokenRequest, type IssuedTokens } from "./token.ts";
import { handleUserinfoRequest, oidccLoadUserInfo, type UserInfo } from "./userinfo.ts";
import { handleWebfingerRequest } from "./webfinger.ts";
import { handleCheckSessionIframeRequest, handleGetSessionStateRequest } from "./session.ts";

/** The variant parameters of the OIDCC RP test modules (upstream variant/*.java values) */
export interface RpVariant {
	client_registration: "dynamic_client" | "static_client";
	client_auth_type:
		| "none"
		| "client_secret_basic"
		| "client_secret_post"
		| "client_secret_jwt"
		| "private_key_jwt"
		| "tls_client_auth"
		| "self_signed_tls_client_auth";
	response_type: "code" | "id_token" | "id_token token" | "code id_token" | "code token" | "code id_token token";
	response_mode: "default" | "form_post";
	request_type: "plain_http_request" | "request_object" | "request_uri";
	[parameter: string]: string;
}

/** What a response_type includes (upstream ResponseType.includesCode / includesIdToken / includesToken) */
export interface ResponseTypeParts {
	includesCode: boolean;
	includesIdToken: boolean;
	includesToken: boolean;
}

export function responseTypeParts(responseType: string): ResponseTypeParts {
	const parts = responseType.split(" ");
	return {
		includesCode: parts.includes("code"),
		includesIdToken: parts.includes("id_token"),
		includesToken: parts.includes("token"),
	};
}

/**
 * How a module's emulated OP differs from the default one. Each option is the upstream method a module overrides,
 * named after what it changes; callbacks run where upstream calls the method and log their own checks.
 */
export interface EmulatedOpOptions {
	/** The discovery document (upstream configureServerConfiguration); default OIDCCGenerateServerConfiguration */
	serverConfiguration?: (baseUrl: string) => ServerMetadata;
	/** The OP's keys (upstream configureServerJWKS + validateConfiguredServerJWKS); default {@link configureServerJwks} */
	serverJwks?: () => ServerKeys | Promise<ServerKeys>;
	/** The id_token signing algorithm for the client (upstream setServerSigningAlgorithm); default OIDCCExtractServerSigningAlg */
	signingAlg?: (client: RpClient, op: EmulatedOp) => string;
	/** Changes to the registered client (upstream getAdditionalClientRegistrationSteps) */
	registrationSteps?: (client: RpClient) => void;
	/** Checks after the nonce was extracted (upstream extractNonceFromAuthorizationEndpointRequestParameters) */
	checkNonce?: (nonce: string | null) => void;
	/** The response_type check (upstream validateResponseTypeAuthorizationRequestParameter); default EnsureResponseTypeIs<variant> */
	checkResponseType?: (params: AuthorizationParams) => void;
	/** Checks after the standard authorization request checks (upstream validateAuthorizationEndpointRequestParameters) */
	checkAuthorizationRequest?: (params: AuthorizationParams, scope: string) => void;
	/** Accept max_age=0 with prompt=none (upstream disallowMaxAge0AndPromptNone overridden) */
	allowMaxAgeZeroWithPromptNone?: boolean;
	/** Changes to the authorization response parameters (upstream customizeAuthorizationEndpointResponseParams) */
	customizeAuthorizationResponse?: (params: Record<string, string>) => void;
	/** Changes to the id_token claims right after they are generated (upstream generateIdTokenClaims override) */
	idTokenClaims?: (claims: IdTokenClaims, op: EmulatedOp) => void;
	/** Signs the id_token instead of OIDCCSignIdToken (upstream signIdToken) */
	signIdToken?: (claims: IdTokenClaims, op: EmulatedOp) => string | Promise<string>;
	/** Changes the signed id_token (upstream customizeIdTokenSignature) */
	idTokenSignature?: (idToken: string) => string;
	/** Runs when the RP exchanges a code, after client authentication (upstream authorizationCodeGrantType override) */
	onCodeExchange?: () => void;
	/** Runs when the RP calls userinfo, before anything is checked (upstream handleUserinfoEndpointRequest override) */
	onUserinfoRequest?: () => void;
	/** Changes to the userinfo response (upstream prepareUserinfoResponse override) */
	userinfo?: (response: UserInfo) => void;
	/** The client authentication to require instead of the variant's (upstream getEffectiveClientAuthTypeVariant) */
	clientAuthType?: RpVariant["client_auth_type"];
	/**
	 * Runs when a request to `endpoint` arrives, before the OP handles it (upstream handleClientRequestForPath /
	 * handle<Endpoint>EndpointRequest overrides): a check that fails ends the test, state may change (key rotation)
	 */
	onRequest?: (endpoint: Endpoint, request: IncomingRequest, op: EmulatedOp) => void | Promise<void>;
	/**
	 * Checks / changes after the standard client metadata checks, on the registration request or the static client
	 * (upstream validateClientMetadata override)
	 */
	checkClientMetadata?: (client: Record<string, unknown>) => void;
	/** Checks after the standard request object checks (upstream validateRequestObject override) */
	checkRequestObject?: (requestObject: ParsedJwt) => void;
	/** The name of the authorization endpoint's block (upstream getAuthorizationEndpointBlockText) */
	authorizationBlock?: (op: EmulatedOp) => string;
	/** Checks the resource syntax of a webfinger request (upstream validateWebfingerRequestResource) */
	validateWebfingerResource?: (resourcePrefix: "acct" | "https") => void;
	/** Changes to the id_token claims right before signing (upstream addCustomValuesToIdToken) */
	customIdTokenClaims?: (claims: IdTokenClaims, op: EmulatedOp) => void;
	/** The client metadata checks instead of the default ones (upstream validateClientMetadata override) */
	validateClientMetadata?: (client: Record<string, unknown>, server: ServerMetadata) => void | Promise<void>;
	/** Runs when the RP sends an authorization request, before anything is checked (upstream handleAuthorizationEndpointRequest override) */
	onAuthorizationRequest?: () => void;
	/**
	 * Serves the logout and session management endpoints (end_session_endpoint, check_session_iframe, ...) with the
	 * module's behaviour (upstream AbstractOIDCCClientLogoutTest); built by logoutTestOptions() in src/rp/logout.ts
	 */
	logout?: LogoutOptions;
	/**
	 * suite-vs-suite (tests/suite-target.ts): the OP is the implementation under test of an OP test, not the OP of an
	 * RP test. A failed check on a request ends nothing: the endpoint answers with the OAuth error response an OP
	 * gives (an error redirect, an error page when the client or redirect_uri is unknown, a 400 / 401 JSON error);
	 * the OP serves several registered clients (each with its authorization, tokens and refresh token), accepts
	 * request objects by value or by reference whatever the variant says, keeps the user's auth_time between flows
	 * (a session: prompt=login and an exceeded max_age authenticate afresh, prompt=none without a session is
	 * login_required), and exchanges an authorization code once.
	 */
	opUnderTest?: boolean;
	/**
	 * The refresh token modules (upstream AbstractOIDCCClientTestRefreshToken): the OP issues a refresh token with
	 * the code grant and serves the refresh_token grant (announce it with
	 * discovery.oidccGenerateServerConfigurationWithRefreshTokenGrantType)
	 */
	refresh?: RefreshOptions;
}

/** What a refresh token module's OP does with a refresh request (upstream AbstractOIDCCClientTestRefreshToken) */
export interface RefreshOptions {
	/** An id_token in the refresh response (upstream generateIdTokenOnRefreshRequest); default true */
	idToken?: boolean;
	/** A new refresh token in the refresh response (upstream generateRefreshTokenOnRefreshRequest); default true */
	newRefreshToken?: boolean;
	/** Changes to the refresh response's id_token claims (upstream addCustomValuesToIdTokenForRefreshResponse) */
	customIdTokenClaims?: (claims: IdTokenClaims, op: EmulatedOp) => void;
	/** Changes to the refresh response's signed id_token (upstream customizeIdTokenSignatureForRefreshResponse) */
	idTokenSignature?: (idToken: string) => string;
	/**
	 * Fails the test with this message when the RP calls userinfo after the refresh response (the negative modules,
	 * upstream AbstractOIDCCClientTestExpectingNothingAfterRefreshResponse); a userinfo request before it is fine
	 */
	userinfoAfterRefreshFails?: string;
}

/** opUnderTest: an OAuth error the OP under test answers a request with (where an RP test fails a check) */
export class OAuthError extends Error {
	readonly error: string;
	readonly description: string;

	constructor(error: string, description: string) {
		super(`${error}: ${description}`);
		this.name = "OAuthError";
		this.error = error;
		this.description = description;
	}
}

export type Endpoint =
	| "discovery"
	| "jwks"
	| "registration"
	| "authorization"
	| "token"
	| "userinfo"
	| "webfinger"
	| "end_session"
	| "check_session_iframe"
	| "get_session_state"
	| "frontchannel_logout_callback";

/** What expect()/waitFor() resolve with: the request and what the OP answered */
export interface OpEvents {
	discovery: { request: IncomingRequest };
	jwks: { request: IncomingRequest };
	registration: { request: IncomingRequest; client: RpClient };
	authorization: {
		request: IncomingRequest;
		authorization: AuthorizationState;
		/** upstream "authorization_endpoint_response_params" */
		response: Record<string, string>;
	};
	token: { request: IncomingRequest; response: Record<string, unknown> };
	userinfo: { request: IncomingRequest; response: UserInfo };
	/** `response`: the webfinger response, null when the resource does not name this test */
	webfinger: { request: IncomingRequest; response: Record<string, unknown> | null };
	end_session: EndSessionEvent;
	check_session_iframe: { request: IncomingRequest };
	/** `afterLogout`: the request came after the end_session request (the OP iframe answers "changed") */
	get_session_state: { request: IncomingRequest; afterLogout: boolean };
	frontchannel_logout_callback: { request: IncomingRequest };
}

/** The emulated OP of one test: its state (upstream's environment) and the requests the RP sent */
export interface EmulatedOp {
	readonly testName: string;
	readonly variant: RpVariant;
	readonly config: TestConfig;
	readonly options: EmulatedOpOptions;
	/** upstream base_url */
	readonly baseUrl: string;
	/** upstream "issuer": base_url + "/" */
	readonly issuer: string;
	readonly clientAuthType: string;
	readonly responseType: ResponseTypeParts;
	/** upstream "server" */
	readonly metadata: ServerMetadata;
	/** upstream "server_jwks" / "server_public_jwks": replaced when a module rotates the keys */
	keys: ServerKeys;
	/** upstream "user_info" */
	readonly userInfo: UserInfo;
	/** upstream "client" (null until the RP registered) */
	client: RpClient | null;
	/** upstream "client_public_jwks" */
	clientPublicJwks: Jwks | null;
	/** upstream "signing_algorithm" */
	signingAlg: string | null;
	authorization: AuthorizationState | null;
	tokens: IssuedTokens | null;
	/** upstream "refresh_token": the refresh token issued to the client (the refresh token modules) */
	refreshToken: string | null;
	/** upstream receivedRefreshRequest: the RP sent a refresh_token grant */
	receivedRefreshRequest: boolean;
	/** upstream "all_issued_id_tokens": the id_tokens OIDCCSignIdToken signed */
	issuedIdTokens: string[];
	/** opUnderTest: when the user authenticated (the auth_time of the next id_token, unless prompt or max_age say otherwise) */
	sessionAuthTime: number | null;
	/** opUnderTest: the authorization codes already exchanged */
	usedCodes: Set<string>;
	/**
	 * opUnderTest: makes the registered client with `clientId` (or the one `accessToken` was issued to) the current
	 * one, with its authorization, tokens and refresh token; false when there is no such client. Upstream's OP knows
	 * one client, so the other endpoints keep reading `client`.
	 */
	selectClient(by: { clientId: string | null } | { accessToken: string | null }): boolean;
	/** Forgets the requests to `endpoint` not yet taken by expect / waitFor (upstream: receivedUserinfoRequest = false) */
	discardEvents(endpoint: Endpoint): void;
	/** The id_token signing algorithm for `client` (the signingAlg option or OIDCCExtractServerSigningAlg) */
	chooseSigningAlg(client: RpClient): string;
	/**
	 * The next request to `endpoint` (already answered). Fails when the RP under test finished without sending
	 * one, after `timeoutSeconds` (60), or when handling a request failed the test.
	 */
	expect<E extends Endpoint>(endpoint: E, opts?: { timeoutSeconds?: number }): Promise<OpEvents[E]>;
	/**
	 * The next request to `endpoint` within `seconds`, or null when none came (or the RP under test finished):
	 * upstream's startWaitingForTimeout, where the RP may (or must not) continue.
	 */
	waitFor<E extends Endpoint>(endpoint: E, seconds: number): Promise<OpEvents[E] | null>;
	/**
	 * The client: registered by the RP at the registration endpoint (dynamic_client, waits for the registration
	 * request like expect()) or the configured one (static_client)
	 */
	clientRegistered(): Promise<RpClient>;
	/** The RP under test reported that it finished (its client driver call returned) */
	rpFinished(): void;
	/** How many requests to `endpoint` the OP has answered (upstream's received<Endpoint>Request flags) */
	received(endpoint: Endpoint): number;
}

/**
 * Ends the test with a failure from a request handler (upstream: a module throwing TestFailureException(msg)),
 * logged under the module's name.
 */
export function failTest(msg: string): never {
	logModule({ msg, result: "FAILURE", error: msg, error_class: "TestFailureException" });
	throw new ConditionFailed(currentContext().testName, msg, "FAILURE");
}

/** opUnderTest: what `op` holds for one registered client */
interface ClientState {
	client: RpClient;
	clientPublicJwks: Jwks | null;
	signingAlg: string | null;
	authorization: AuthorizationState | null;
	tokens: IssuedTokens | null;
	refreshToken: string | null;
}

/**
 * opUnderTest: the OAuth error response for a request whose handling failed a check (or threw an OAuthError): an
 * error redirect to a registered redirect_uri of the named client (query, fragment or form_post as the request asks),
 * else an error page; a 400 / 401 JSON error at the other endpoints.
 */
function opUnderTestErrorResponse(op: EmulatedOp, endpoint: Endpoint, req: IncomingRequest, e: unknown): Response {
	const { error, description, status, noRedirect } = oauthError(endpoint, e);
	if (endpoint === "authorization") {
		const params = req.method === "POST" ? (req.body_form_params ?? {}) : req.query_string_params;
		const str = (name: string) => (typeof params[name] === "string" ? params[name] : null);
		const redirectUri = str("redirect_uri");
		const client = op.client;
		const redirectUris = Array.isArray(client?.["redirect_uris"]) ? client["redirect_uris"] : [];
		const registered =
			client?.client_id === str("client_id") && redirectUri != null && redirectUris.includes(redirectUri);
		if (registered && !noRedirect) {
			const response: Record<string, string> = { error, error_description: description };
			const state = str("state");
			if (state != null) {
				response["state"] = state;
			}
			if (str("response_mode") === "form_post") {
				return formPostResponsePage({ redirect_uri: redirectUri, ...response });
			}
			const url = new URL(redirectUri);
			const query = new URLSearchParams(response).toString();
			if (str("response_mode") === "fragment" || /\b(id_token|token)\b/.test(str("response_type") ?? "")) {
				url.hash = query;
			} else {
				url.search = (url.search ? url.search + "&" : "?") + query;
			}
			return new Response(null, { status: 302, headers: { location: url.toString() } });
		}
		const html = `<!DOCTYPE html><html><head><title>Authorization request error</title></head><body><h1>Authorization request error</h1><p>${escapeHtml(error)}: ${escapeHtml(description)}</p></body></html>`;
		return htmlResponse(html, 400);
	}
	const headers =
		endpoint === "userinfo"
			? { "www-authenticate": `Bearer error="${error}", error_description="${description.replaceAll('"', "'")}"` }
			: undefined;
	return Response.json({ error, error_description: description }, { status, headers });
}

/** The OAuth error (RFC 6749 4.1.2.1 / 5.2, RFC 6750 3.1) a failed check of `endpoint` stands for */
function oauthError(
	endpoint: Endpoint,
	e: unknown,
): { error: string; description: string; status: number; noRedirect: boolean } {
	if (e instanceof OAuthError) {
		return {
			error: e.error,
			description: e.description,
			status: e.error === "invalid_client" ? 401 : 400,
			noRedirect: false,
		};
	}
	const name = e instanceof ConditionFailed ? e.condition : "";
	const description = e instanceof Error ? e.message : String(e);
	const result = (error: string, status = 400, noRedirect = false) => ({ error, description, status, noRedirect });
	switch (endpoint) {
		case "authorization":
			if (/ResponseType/.test(name)) {
				return result("unsupported_response_type");
			}
			if (/Scope/.test(name)) {
				return result("invalid_scope");
			}
			// an unknown client or redirect_uri must not be redirected to
			return result("invalid_request", 400, /EnsureMatchingClientId|RedirectUri/.test(name));
		case "token":
			if (/ClientCredentials|ClientIdAndSecret|ClientAuthentication/.test(name)) {
				return result("invalid_client", 401);
			}
			if (/AuthorizationCode|RefreshToken|RedirectUriForTokenEndpoint/.test(name)) {
				return result("invalid_grant");
			}
			if (/Scope/.test(name)) {
				return result("invalid_scope");
			}
			return result("invalid_request");
		case "userinfo":
			return result("invalid_token", 401);
		default:
			return result("invalid_request");
	}
}

interface Waiter {
	endpoint: Endpoint;
	resolve: (event: unknown) => void;
	reject: (e: unknown) => void;
	/** waitFor(): resolve null instead of rejecting when the RP finished */
	optional: boolean;
}

/**
 * Sets the OP up (upstream configure: metadata, keys, user, static client) and serves its endpoints on `server`.
 *
 * upstream: openid/client/AbstractOIDCCClientTest.java (configure, handleHttp, handleClientRequestForPath)
 */
export async function startEmulatedOp(
	server: TestServer,
	ctx: { testName: string; variant: RpVariant; config: TestConfig },
	options: EmulatedOpOptions = {},
): Promise<EmulatedOp> {
	const { variant, config } = ctx;
	const clientAuthType = options.clientAuthType ?? variant.client_auth_type;
	if (clientAuthType === "tls_client_auth" || clientAuthType === "self_signed_tls_client_auth") {
		throw new Error(`TODO(port): client_auth_type=${clientAuthType} (ChangeTokenEndpointInServerConfigurationToMtls)`);
	}

	const metadata = (options.serverConfiguration ?? oidccGenerateServerConfiguration)(server.baseUrl);
	setTokenEndpointAuthMethodsSupportedOnly(metadata, clientAuthType);
	if (options.opUnderTest) {
		// an OP under test takes request objects by value and by reference
		configureRequestObjectSupport(metadata, "request_object");
		configureRequestObjectSupport(metadata, "request_uri");
	} else {
		configureRequestObjectSupport(metadata, variant.request_type);
	}
	ensureServerConfigurationHasRequiredOidcMetadata(metadata, "OIDCD-3");
	const keys = await (options.serverJwks ?? configureServerJwks)();
	const userInfo = oidccLoadUserInfo();

	const events = new Map<Endpoint, unknown[]>();
	const counts = new Map<Endpoint, number>();
	const waiters: Waiter[] = [];
	let failure: { error: unknown } | null = null;
	let finished = false;

	const op: EmulatedOp = {
		testName: ctx.testName,
		variant,
		config,
		options,
		baseUrl: server.baseUrl,
		issuer: server.baseUrl + "/",
		clientAuthType,
		responseType: responseTypeParts(variant.response_type),
		metadata,
		keys,
		userInfo,
		client: null,
		clientPublicJwks: null,
		signingAlg: null,
		authorization: null,
		tokens: null,
		refreshToken: null,
		receivedRefreshRequest: false,
		issuedIdTokens: [],
		sessionAuthTime: null,
		usedCodes: new Set(),
		selectClient,
		discardEvents(endpoint) {
			events.delete(endpoint);
		},
		chooseSigningAlg: (client) =>
			options.signingAlg ? options.signingAlg(client, op) : oidccExtractServerSigningAlg(client, op.keys.jwks),
		expect(endpoint, opts = {}) {
			return currentContext().step(`The RP sends a ${endpoint} request`, () =>
				next(endpoint, opts.timeoutSeconds ?? 60, false),
			) as Promise<never>;
		},
		waitFor(endpoint, seconds) {
			return currentContext().step(`The RP may send a ${endpoint} request within ${seconds} seconds`, () =>
				next(endpoint, seconds, true),
			) as Promise<never>;
		},
		async clientRegistered() {
			if (variant.client_registration === "static_client") {
				return op.client as RpClient;
			}
			return (await op.expect("registration")).client;
		},
		rpFinished() {
			finished = true;
			for (const w of waiters.splice(0)) {
				if (w.optional) {
					w.resolve(null);
				} else {
					w.reject(new Error(`The relying party under test finished without sending a ${w.endpoint} request`));
				}
			}
		},
		received: (endpoint) => counts.get(endpoint) ?? 0,
	};

	// opUnderTest: the state of every registered client; the current client's is on `op` (upstream knows one client)
	const clientStates = new Map<string, ClientState>();
	function saveClientState(): void {
		if (op.client != null) {
			const { client, clientPublicJwks, signingAlg, authorization, tokens, refreshToken } = op;
			clientStates.set(client.client_id, { client, clientPublicJwks, signingAlg, authorization, tokens, refreshToken });
		}
	}
	function selectClient(by: { clientId: string | null } | { accessToken: string | null }): boolean {
		saveClientState();
		const state =
			"clientId" in by
				? by.clientId == null
					? undefined
					: clientStates.get(by.clientId)
				: [...clientStates.values()].find((s) => by.accessToken != null && s.tokens?.accessToken === by.accessToken);
		if (state == null) {
			return false;
		}
		Object.assign(op, state);
		return true;
	}

	function next(endpoint: Endpoint, seconds: number, optional: boolean): Promise<unknown> {
		if (failure) {
			return Promise.reject(failure.error);
		}
		const queued = events.get(endpoint);
		if (queued && queued.length > 0) {
			return Promise.resolve(queued.shift());
		}
		if (finished) {
			return optional
				? Promise.resolve(null)
				: Promise.reject(new Error(`The relying party under test finished without sending a ${endpoint} request`));
		}
		const { promise, resolve, reject } = Promise.withResolvers<unknown>();
		const waiter: Waiter = { endpoint, resolve, reject, optional };
		waiters.push(waiter);
		const timer = setTimeout(() => {
			const i = waiters.indexOf(waiter);
			if (i !== -1) {
				waiters.splice(i, 1);
			}
			if (optional) {
				resolve(null);
			} else {
				reject(new Error(`Timed out after ${seconds} seconds waiting for the relying party's ${endpoint} request`));
			}
		}, seconds * 1000);
		return promise.finally(() => clearTimeout(timer));
	}

	function record(endpoint: Endpoint, event: unknown): void {
		counts.set(endpoint, (counts.get(endpoint) ?? 0) + 1);
		const i = waiters.findIndex((w) => w.endpoint === endpoint);
		if (i !== -1) {
			waiters.splice(i, 1)[0].resolve(event);
			return;
		}
		const queue = events.get(endpoint) ?? [];
		queue.push(event);
		events.set(endpoint, queue);
	}

	// the handlers log into the log of the context the OP was started in (the test's, or the emulated OP's own when
	// another test talks to it: suite-vs-suite), whatever context the server delivers the request in
	const opContext = currentContext();
	// requests are handled one at a time, like upstream's per-test lock
	let lock: Promise<unknown> = Promise.resolve();
	function serve(
		endpoint: Endpoint,
		path: string,
		handle: (req: IncomingRequest) => Promise<{ response: Response; event: unknown }>,
		/** concurrent: handled without waiting for the lock (a read-only endpoint the RP calls while the OP waits for it) */
		opts: { concurrent?: boolean } = {},
	) {
		server.on(path, (req) => {
			const run = (opts.concurrent ? Promise.resolve() : lock).then(async (): Promise<Response> => {
				if (failure && endpoint !== "jwks" && endpoint !== "discovery") {
					return Response.json({ error: "server_error", error_description: "The test has failed" }, { status: 500 });
				}
				try {
					// a request handler is not a Playwright step of the test: blocks only go to the log
					const { response, event } = await withContext(
						{ ...opContext, severity: "failure", step: (_name, fn) => fn() },
						async () => {
							await options.onRequest?.(endpoint, req, op);
							return handle(req);
						},
					);
					record(endpoint, event);
					return response;
				} catch (e) {
					if (options.opUnderTest) {
						// the OP under test answers as an OP does; the failed check stays in its log
						return opUnderTestErrorResponse(op, endpoint, req, e);
					}
					if (!failure) {
						failure = { error: e };
						for (const w of waiters.splice(0)) {
							w.reject(e);
						}
					}
					return Response.json(
						{ error: "server_error", error_description: (e as Error).message ?? String(e) },
						{ status: 500 },
					);
				}
			});
			if (!opts.concurrent) {
				lock = run.catch(() => {});
			}
			return run;
		});
	}

	// the endpoints are where the metadata says: a module may move the issuer (webfinger) or the jwks_uri
	const relative = (url: unknown, fallback: string) =>
		typeof url === "string" && url.startsWith(server.baseUrl + "/")
			? url.substring(server.baseUrl.length + 1)
			: fallback;
	const issuerPath = relative(metadata.issuer, "").replace(/\/$/, "");
	const discoveryPaths = [".well-known/openid-configuration"];
	if (issuerPath !== "") {
		discoveryPaths.push(issuerPath + "/.well-known/openid-configuration");
	}
	for (const path of discoveryPaths) {
		serve("discovery", path, async (request) => {
			await block("Discovery endpoint", () => {});
			return { response: discoveryResponse(metadata), event: { request } };
		});
	}
	// concurrent: the RP fetches the keys while the OP waits for its back-channel logout response
	serve(
		"jwks",
		relative(metadata.jwks_uri, "jwks"),
		async (request) => {
			await block("Jwks endpoint", () => {});
			return { response: jwksResponse(op.keys), event: { request } };
		},
		{ concurrent: true },
	);
	// upstream env "issuer": the issuer the configuration was generated with
	const configuredIssuer = metadata.issuer as string;
	serve("webfinger", "/.well-known/webfinger", async (request) => {
		const { response, webfinger } = await handleWebfingerRequest(op, request, configuredIssuer);
		return { response, event: { request, response: webfinger } };
	});
	if (variant.client_registration === "dynamic_client") {
		serve("registration", "register", async (request) => {
			if (options.opUnderTest) {
				// another client: the current one's state is kept, the new one starts without flows
				saveClientState();
				op.authorization = null;
				op.tokens = null;
				op.refreshToken = null;
			}
			const { response, client } = await handleRegistrationRequest(op, request);
			return { response, event: { request, client } };
		});
	}
	serve("authorization", "authorize", async (request) => {
		options.onAuthorizationRequest?.();
		const { response, authorization, responseParams } = await handleAuthorizationRequest(op, request);
		return { response, event: { request, authorization, response: responseParams } };
	});
	serve("token", "token", async (request) => {
		const { response, tokens } = await handleTokenRequest(op, request);
		return { response, event: { request, response: tokens } };
	});
	serve("userinfo", "userinfo", async (request) => {
		options.onUserinfoRequest?.();
		const { response, userinfo } = await handleUserinfoRequest(op, request, options.userinfo);
		return { response, event: { request, response: userinfo } };
	});

	const logout = options.logout;
	if (logout) {
		serve("end_session", "end_session_endpoint", async (request) => {
			const { response, event } = await handleEndSessionRequest(op, request, logout);
			return { response, event: { ...event, request } };
		});
		serve("check_session_iframe", "check_session_iframe", async (request) => {
			const response = await handleCheckSessionIframeRequest(op.baseUrl);
			return { response, event: { request } };
		});
		serve("get_session_state", "get_session_state", async (request) => {
			const { response, afterLogout } = await handleGetSessionStateRequest(logout.session);
			return { response, event: { request, afterLogout } };
		});
		serve("frontchannel_logout_callback", "frontchannel_logout_callback", async (request) => {
			const response = await handleFrontChannelLogoutCallback();
			return { response, event: { request } };
		});
	}

	// the client: from the configuration (static_client) or registered by the RP later (dynamic_client)
	if (variant.client_registration === "static_client") {
		const client = oidccGetStaticClientConfigurationForRPTests(config);
		op.clientPublicJwks = await processAndValidateClientJwks(client, clientAuthType, variant.request_type);
		await (options.validateClientMetadata ?? validateClientMetadata)(client, metadata);
		options.checkClientMetadata?.(client);
		op.client = client;
		op.signingAlg = op.chooseSigningAlg(client);
		setClientIdTokenSignedResponseAlgToServerSigningAlg(client, op.signingAlg);
	} else {
		// the result of these is not used (upstream: "I am not sure the result of either of these condition calls is used")
		const original = soft(() => storeOriginalClientConfiguration(config), "info") ?? {};
		extractClientNameFromStoredConfig(original);
	}
	return op;
}

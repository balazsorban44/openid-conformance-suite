/**
 * RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0) and its back-channel / front-channel notifications:
 * the URIs the suite registers, the end_session_endpoint request, sending the browser there and receiving the
 * post logout redirect, the back-channel logout token and the front-channel logout request, and the checks on them.
 *
 *   const postLogoutRedirectUri = logout.createPostLogoutRedirectUri(op.baseUrl, "OIDCRIL-2", "OIDCRIL-3");
 *   const client = await configureClient((request) =>
 *     logout.addPostLogoutRedirectUriToDynamicRegistrationRequest(request, postLogoutRedirectUri, "OIDCRIL-3.1"));
 *   const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);
 *   const { state, url } = ... createRandomEndSessionState / createEndSessionEndpointRequest / buildRedirectToEndSessionEndpoint
 *   const redirect = await logout.redirectToEndSessionEndpoint(op, url);
 *   logout.checkPostLogoutState(redirect, state, "OIDCRIL-2");
 *   await logout.verifyLoggedOutWithPromptNone(op, client);
 *
 * The suite's endpoints (below its base url): post_logout_redirect, backchannel_logout, frontchannel_logout.
 */
import { randomInt } from "node:crypto";
import { block, condition, logModule, soft, type Condition } from "../suite/conditions.ts";
import { escapeHtml } from "../suite/log.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import { parseJwt, signJwt, verifyJwsSignature, type ParsedJwt } from "../suite/jose.ts";
import { htmlResponse, type IncomingRequest } from "../suite/server.ts";
import { JWTUtil } from "../util/JWTUtil.ts";
import { JOSEException, ParseException } from "../util/nimbus/errors.ts";
import { toUriString } from "../util/UriComponentsBuilder.ts";
import * as authz from "./authorization.ts";
import type { AuthorizationRequest, AuthorizationResponse } from "./authorization.ts";
import type { ServerMetadata } from "./discovery.ts";
import { ensureHttpStatusCodeIs200 } from "./endpoint.ts";
import * as idToken from "./id-token.ts";
import type { Op } from "./op.ts";
import type { Client, RegisteredClient } from "./registration.ts";
import * as token from "./token.ts";
import type { Tokens } from "./token.ts";
import { callProtectedResource } from "./userinfo.ts";

/** The end_session_endpoint request parameters (upstream env "end_session_endpoint_request") */
export type EndSessionRequest = Record<string, string>;

// ---- the URIs the suite registers ----

/** upstream: condition/client/CreatePostLogoutRedirectUri.java */
export function createPostLogoutRedirectUri(baseUrl: string, ...requirements: string[]): string {
	const c: Condition = condition("CreatePostLogoutRedirectUri", ...requirements);
	if (!baseUrl) {
		c.failure("Base URL is empty");
	}
	const uri = baseUrl + "/post_logout_redirect";
	c.success("Created post_logout_redirect_uri URI", { post_logout_redirect_uri: uri });
	return uri;
}

/** upstream: condition/client/AddPostLogoutRedirectUriToDynamicRegistrationRequest.java */
export function addPostLogoutRedirectUriToDynamicRegistrationRequest(
	registrationRequest: Record<string, unknown>,
	postLogoutRedirectUri: string,
	...requirements: string[]
): void {
	registrationRequest["post_logout_redirect_uris"] = [postLogoutRedirectUri];
	condition("AddPostLogoutRedirectUriToDynamicRegistrationRequest", ...requirements).log(
		"Added post_logout_redirect_uris to dynamic registration request",
		{ dynamic_registration_request: registrationRequest },
	);
}

/**
 * upstream: condition/client/CreateBackchannelLogoutUri.java (upstream's external_url_override is the server's
 * externalUrl here, already part of `baseUrl`)
 */
export function createBackchannelLogoutUri(baseUrl: string, ...requirements: string[]): string {
	const c: Condition = condition("CreateBackchannelLogoutUri", ...requirements);
	if (baseUrl === "") {
		c.failure("Base URL is empty");
	}
	const uri = baseUrl + "/backchannel_logout";
	c.success("Created backchannel_logout_uri URI", { backchannel_logout_uri: uri });
	return uri;
}

/** upstream: condition/client/AddBackchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest.java */
export function addBackchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest(
	registrationRequest: Record<string, unknown>,
	...requirements: string[]
): void {
	registrationRequest["backchannel_logout_session_required"] = true;
	condition("AddBackchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest", ...requirements).log(
		"Added backchannel_logout_session_required: true to dynamic registration request",
		{ dynamic_registration_request: registrationRequest },
	);
}

/** upstream: condition/client/AddBackchannelLogoutUriToDynamicRegistrationRequest.java */
export function addBackchannelLogoutUriToDynamicRegistrationRequest(
	registrationRequest: Record<string, unknown>,
	backchannelLogoutUri: string,
	...requirements: string[]
): void {
	registrationRequest["backchannel_logout_uri"] = backchannelLogoutUri;
	condition("AddBackchannelLogoutUriToDynamicRegistrationRequest", ...requirements).log(
		"Added backchannel_logout_uri to dynamic registration request",
		{ dynamic_registration_request: registrationRequest },
	);
}

/** upstream: condition/client/CreateFrontchannelLogoutUri.java */
export function createFrontchannelLogoutUri(baseUrl: string, ...requirements: string[]): string {
	const c: Condition = condition("CreateFrontchannelLogoutUri", ...requirements);
	if (baseUrl.length === 0) {
		c.failure("Base URL is empty");
	}
	const uri = baseUrl + "/frontchannel_logout";
	c.success("Created frontchannel_logout_uri URI", { frontchannel_logout_uri: uri });
	return uri;
}

/** upstream: condition/client/AddFrontchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest.java */
export function addFrontchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest(
	registrationRequest: Record<string, unknown>,
	...requirements: string[]
): void {
	registrationRequest["frontchannel_logout_session_required"] = true;
	condition("AddFrontchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest", ...requirements).log(
		"Added frontchannel_logout_session_required: true to dynamic registration request",
		{ dynamic_registration_request: registrationRequest },
	);
}

/** upstream: condition/client/AddFrontchannelLogoutUriToDynamicRegistrationRequest.java */
export function addFrontchannelLogoutUriToDynamicRegistrationRequest(
	registrationRequest: Record<string, unknown>,
	frontchannelLogoutUri: string,
	...requirements: string[]
): void {
	registrationRequest["frontchannel_logout_uri"] = frontchannelLogoutUri;
	condition("AddFrontchannelLogoutUriToDynamicRegistrationRequest", ...requirements).log(
		"Added frontchannel_logout_uri to dynamic registration request",
		{ dynamic_registration_request: registrationRequest },
	);
}

// ---- logging in, and checking the user is logged out ----

/**
 * The logout tests use a 128 character state, to check the OP does not corrupt it.
 *
 * upstream: AbstractOIDCCRpInitiatedLogout.onConfigure (requested_state_length)
 */
const STATE_LENGTH = 128;

/**
 * The authorization request of the logout tests: upstream's CreateAuthorizationRequestSteps with a 128 character
 * state; the second authorization (after the logout) adds prompt=none.
 *
 * upstream: AbstractOIDCCRpInitiatedLogout.createAuthorizationRequest + AbstractOIDCCServerTest.createAuthorizationRedirect
 */
export function createAuthorizationRequest(
	op: Pick<Op, "metadata" | "redirectUri" | "variant">,
	client: Client,
	opts: { promptNone?: boolean } = {},
): AuthorizationRequest {
	const responseType = op.variant.response_type;
	const responseMode = op.variant.response_mode;
	const params = authz.createAuthorizationEndpointRequestFromClientInformation(client, op.redirectUri);
	const state = authz.createRandomStateValue(STATE_LENGTH);
	authz.addStateToAuthorizationEndpointRequest(params, state);
	const nonce = authz.createRandomNonceValue();
	authz.addNonceToAuthorizationEndpointRequest(params, nonce);
	authz.setAuthorizationEndpointRequestResponseType(params, responseType);
	if (responseMode === "form_post") {
		authz.setAuthorizationEndpointRequestResponseModeToFormPost(params);
	}
	if (opts.promptNone) {
		authz.addPromptNoneToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1");
	}
	const url = authz.buildPlainRedirectToAuthorizationEndpoint(op, params);
	return { params, state, nonce, redirectUri: op.redirectUri, responseType, responseMode, url };
}

/**
 * Logs the user in with the code flow: the authorization request, the code exchange with the standard id_token
 * checks, and a userinfo call with the access token.
 *
 * upstream: AbstractOIDCCServerTest.performAuthorizationFlow up to onPostAuthorizationFlowComplete, as the logout
 * modules run it (the first time)
 */
export async function performAuthorizationFlow(
	op: Op,
	client: RegisteredClient,
	userinfoUrl: string,
): Promise<{ request: AuthorizationRequest; response: AuthorizationResponse; tokens: Tokens }> {
	if (op.variant.response_type !== "code") {
		throw new Error(`response_type '${op.variant.response_type}' is not supported by src/op/logout.ts yet`);
	}
	const request = await block("Make request to authorization endpoint", () =>
		createAuthorizationRequest(op, client.client),
	);
	const response = await authz.authorize(op, request);

	const tokens = await block("Verify authorization endpoint response", async () => {
		authz.checkAuthorizationResponse(op, request, response);
		const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
		const tokenRequest = await token.createAuthorizationCodeRequest(op, client, code);
		const result = await token.requestAuthorizationCode(op, client, tokenRequest);
		await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
		return result;
	});

	// UPSTREAM: AbstractOIDCCRpInitiatedLogout clears its firstTime flag before the code is exchanged, so the
	// userinfo block of the first authorization is already named "Second authorization: ..."
	await block("Second authorization: Userinfo endpoint tests", async () => {
		const res = await callProtectedResource(userinfoUrl, tokens.accessToken);
		soft(() => ensureHttpStatusCodeIs200(res));
	});
	return { request, response, tokens };
}

/**
 * After the logout, an authorization request with prompt=none must fail with an error saying a user interface is
 * needed: the user is no longer logged in.
 *
 * upstream: AbstractOIDCCRpInitiatedLogout.createAuthorizationRequest / onAuthorizationCallbackResponse (the second
 * time)
 */
export async function verifyLoggedOutWithPromptNone(op: Op, client: RegisteredClient): Promise<void> {
	const request = await block("Second authorization: Make request to authorization endpoint", () =>
		createAuthorizationRequest(op, client.client, { promptNone: true }),
	);
	const response = await authz.authorize(op, request);
	await block("Second authorization: Verify authorization endpoint response", () => {
		authz.checkCallbackLocation(request, response);
		authz.checkAuthorizationErrorResponse(op, request, response);
		soft(() => authz.checkErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface(response, "OIDCC-3.1.2.6"));
	});
}

// ---- the end_session_endpoint request ----

/** The characters of the ranges (upstream RandomStringGenerator.Builder().withinRange(pairs)) */
function charRange(pairs: [string, string][]): string[] {
	return pairs.flatMap(([from, to]) =>
		Array.from({ length: to.charCodeAt(0) - from.charCodeAt(0) + 1 }, (_, i) =>
			String.fromCharCode(from.charCodeAt(0) + i),
		),
	);
}

function pickRandom(chars: string[], count: number): string {
	return Array.from({ length: count }, () => chars[randomInt(chars.length)]).join("");
}

/** RFC6749 Appendix A VSCHAR (%x20-7E): letters, then digits, then punctuation (upstream RFC6749AppendixASyntaxUtils) */
function randomVSChar(alphaCount: number, numberCount: number, punctuationCount: number): string {
	return (
		pickRandom(
			charRange([
				["a", "z"],
				["A", "Z"],
			]),
			alphaCount,
		) +
		pickRandom(charRange([["0", "9"]]), numberCount) +
		pickRandom(
			charRange([
				[" ", "/"],
				[":", "@"],
				["[", "`"],
				["{", "~"],
			]),
			punctuationCount,
		)
	);
}

/** upstream: condition/client/CreateRandomEndSessionState.java */
export function createRandomEndSessionState(...requirements: string[]): string {
	// the session spec does not define a character set for state; assume RFC6749's. '+' and ' ' are not escaped
	// correctly in the url query, ';' is not processed correctly by spring when returned unescaped
	// (https://gitlab.com/openid/conformance-suite/-/issues/871)
	const state = randomVSChar(50, 10, 30).replaceAll("+", "~").replaceAll(" ", "~").replaceAll(";", "~");
	condition("CreateRandomEndSessionState", ...requirements).log("Created end_session_state value", {
		end_session_state: state,
	});
	return state;
}

/**
 * id_token_hint (the id_token, upstream env "id_token" value), post_logout_redirect_uri and state.
 *
 * upstream: condition/client/CreateEndSessionEndpointRequest.java
 */
export function createEndSessionEndpointRequest(
	idTokenHint: string,
	postLogoutRedirectUri: string,
	state: string,
	...requirements: string[]
): EndSessionRequest {
	const c: Condition = condition("CreateEndSessionEndpointRequest", ...requirements);
	if (!idTokenHint) {
		c.failure("Couldn't find id_token");
	}
	if (!postLogoutRedirectUri) {
		c.failure("Couldn't find post_logout_redirect_uri");
	}
	// UPSTREAM: the end_session_state check tests post_logout_redirect_uri again, so it never fails
	const request: EndSessionRequest = {
		id_token_hint: idTokenHint,
		post_logout_redirect_uri: postLogoutRedirectUri,
		state,
	};
	c.success("Created end session endpoint request", { ...request });
	return request;
}

/** upstream: condition/client/RemoveIdTokenHintFromEndSessionEndpointRequest.java */
export function removeIdTokenHintFromEndSessionEndpointRequest(request: EndSessionRequest): void {
	delete request["id_token_hint"];
	condition("RemoveIdTokenHintFromEndSessionEndpointRequest").success(
		"Removed id_token_hint from end session endpoint request",
		{ ...request },
	);
}

/** upstream: condition/client/RemovePostLogoutRedirectUriFromEndSessionEndpointRequest.java */
export function removePostLogoutRedirectUriFromEndSessionEndpointRequest(request: EndSessionRequest): void {
	delete request["post_logout_redirect_uri"];
	condition("RemovePostLogoutRedirectUriFromEndSessionEndpointRequest").success(
		"Removed post_logout_redirect_uri from end session endpoint request",
		{ ...request },
	);
}

/** upstream: condition/client/RemoveStateFromEndSessionEndpointRequest.java */
export function removeStateFromEndSessionEndpointRequest(request: EndSessionRequest): void {
	delete request["state"];
	condition("RemoveStateFromEndSessionEndpointRequest").success("Removed state from end session endpoint request", {
		...request,
	});
}

/** upstream: condition/client/RemoveAllParametersFromEndSessionEndpointRequest.java */
export function removeAllParametersFromEndSessionEndpointRequest(request: EndSessionRequest): void {
	for (const key of Object.keys(request)) {
		delete request[key];
	}
	condition("RemoveAllParametersFromEndSessionEndpointRequest").success(
		"Removed all parameters from end session endpoint request",
	);
}

/** upstream: condition/client/AddBadPostLogoutRedirectUriToEndSessionEndpointRequest.java */
export function addBadPostLogoutRedirectUriToEndSessionEndpointRequest(
	request: EndSessionRequest,
	baseUrl: string,
): void {
	// this url should not be called (it is not registered)
	request["post_logout_redirect_uri"] = baseUrl + "/bad_post_logout_redirect_uri";
	condition("AddBadPostLogoutRedirectUriToEndSessionEndpointRequest").success(
		"Added bad post_logout_redirect_uri to end session endpoint request",
		{ ...request },
	);
}

/** upstream: condition/client/AddPostLogoutRedirectUriWithQueryAddedToEndSessionEndpointRequest.java */
export function addPostLogoutRedirectUriWithQueryAddedToEndSessionEndpointRequest(request: EndSessionRequest): void {
	request["post_logout_redirect_uri"] = request["post_logout_redirect_uri"] + "?foo=bar";
	condition("AddPostLogoutRedirectUriWithQueryAddedToEndSessionEndpointRequest").success(
		"Added ?foo=bar to post_logout_redirect_uri in end session endpoint request",
		{ ...request },
	);
}

/**
 * The end_session_endpoint URL with the request in its query (in the request's order).
 *
 * upstream: condition/client/BuildRedirectToEndSessionEndpoint.java
 */
export function buildRedirectToEndSessionEndpoint(
	metadata: ServerMetadata,
	request: EndSessionRequest,
	...requirements: string[]
): string {
	const c: Condition = condition("BuildRedirectToEndSessionEndpoint", ...requirements);
	const endpoint = metadata["end_session_endpoint"];
	if (typeof endpoint !== "string" || !endpoint) {
		c.failure("Couldn't find end_session endpoint");
	}
	const url = toUriString(endpoint, Object.entries(request));
	c.success("Sending to end_session endpoint", { redirect_to_end_session_endpoint: url });
	return url;
}

// ---- an id_token_hint the OP must reject ----

/**
 * id_token claims "issued" by the client (iss and aud deliberately swapped).
 *
 * upstream: condition/client/GenerateFakeIdTokenClaims.java
 */
export function generateFakeIdTokenClaims(metadata: ServerMetadata, client: Client): Record<string, unknown> {
	const c: Condition = condition("GenerateFakeIdTokenClaims");
	if (!metadata.issuer) {
		c.failure("Couldn't find issuer");
	}
	if (!client.client_id) {
		c.failure("Couldn't find client ID");
	}
	const iat = Math.floor(Date.now() / 1000);
	const claims = {
		iss: client.client_id,
		sub: "SubjectID",
		aud: metadata.issuer,
		nonce: "flibble",
		iat,
		exp: iat + 300,
	};
	c.success("Created ID Token Claims", claims);
	return claims;
}

/**
 * Signs the fake id_token claims with the client's key; returns the JWS (upstream replaces the id_token value).
 *
 * upstream: condition/client/SignFakeIdToken.java (AbstractSignJWT)
 */
export async function signFakeIdToken(claims: Record<string, unknown>, clientJwks: unknown): Promise<string> {
	const c: Condition = condition("SignFakeIdToken");
	const { jws, verifiable } = await signJwt(c, claims, clientJwks);
	c.success("Signed a 'fake' ID token using the client's keys", { id_token: verifiable });
	return jws;
}

/**
 * The id_token with its header replaced by {"alg": "none"} and the signature removed.
 *
 * upstream: condition/client/ChangeIdTokenToAlgNone.java
 */
export function changeIdTokenToAlgNone(idTokenValue: string): string {
	const c: Condition = condition("ChangeIdTokenToAlgNone");
	if (!idTokenValue) {
		c.failure("Couldn't find id_token");
	}
	try {
		const parsed = JWTUtil.parseJWT(idTokenValue);
		if (parsed.type !== "signed") {
			throw new ParseException("Not a JWS header");
		}
		const jwt = Buffer.from('{"alg": "none"}').toString("base64url") + "." + parsed.parts[1] + ".";
		c.success("Changed id_token to be 'signed' with 'alg: none'", { id_token: jwt });
		return jwt;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse JWT", e, { id_token: idTokenValue });
		}
		throw e;
	}
}

// ---- screenshots of the OP's pages ----

/** A REVIEW entry the browser automation fills with a screenshot (upstream createBrowserInteractionPlaceholder) */
function browserInteractionPlaceholder(name: string, msg: string, requirements: string[]): string {
	const upload = randomAlphanumeric(10);
	condition(name, ...requirements).review(msg, { upload });
	return upload;
}

/** upstream: condition/client/ExpectInvalidIdTokenHintErrorPage.java */
export function expectInvalidIdTokenHintErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectInvalidIdTokenHintErrorPage",
		"The server must show an error page saying the request is invalid as the id_token_hint is not valid - upload a screenshot of the error page.",
		requirements,
	);
}

/** upstream: condition/client/ExpectIdTokenHintRequiredErrorPage.java */
export function expectIdTokenHintRequiredErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectIdTokenHintRequiredErrorPage",
		"The server must show an error page saying the request is invalid as the id_token_hint is missing - upload a screenshot of the error page.",
		requirements,
	);
}

/** upstream: condition/client/ExpectPostLogoutRedirectUriNotRegisteredErrorPage.java */
export function expectPostLogoutRedirectUriNotRegisteredErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectPostLogoutRedirectUriNotRegisteredErrorPage",
		"The server must show an error page saying the request is invalid as the post_logout_redirect_uri is not a registered one - upload a screenshot of the error page.",
		requirements,
	);
}

/** upstream: condition/client/ExpectSuccessfulLogoutPage.java */
export function expectSuccessfulLogoutPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectSuccessfulLogoutPage",
		"The server must log the user out - upload a screenshot of the successful logout page.",
		requirements,
	);
}

// ---- the front channel: sending the browser to the end_session_endpoint ----

/** upstream templates/resultCaptured.html: what the browser sees when it comes back to the suite */
export function resultCapturedPage(testId: string): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OIDF Conformance: Result Captured</title>
</head>
<body>
    <div>
        <h1>Result captured</h1>
        <p>The test suite has received the result. You may return to <a href="${escapeHtml("/log-detail.html?log=" + testId)}">the test results page.</a></p>
    </div>
</body>
</html>`;
}

function redirectingToEndSessionEndpoint(url: string): void {
	logModule({ msg: "Redirecting to end session endpoint", redirect_to: url, http: "redirect" });
}

/**
 * Sends the browser to the end_session_endpoint (the configuration's browser automation confirms the logout) and
 * resolves with the redirect back to the post_logout_redirect_uri (upstream requestParts).
 *
 * upstream: AbstractOIDCCRpInitiatedLogout.performRedirectToEndSessionEndpoint + OIDCCRpInitiatedLogout.handlePostLogoutRedirect
 */
export async function redirectToEndSessionEndpoint(op: Op, url: string): Promise<IncomingRequest> {
	redirectingToEndSessionEndpoint(url);
	const [redirect] = await Promise.all([
		op.server.waitFor("post_logout_redirect", htmlResponse(resultCapturedPage(op.testId)), { timeoutSeconds: 120 }),
		op.browser.visit(url),
	]);
	return redirect;
}

/**
 * Sends the browser to the end_session_endpoint where the OP must not redirect back to the post_logout_redirect_uri
 * but show a page (an error, a logout confirmation or the logged out page) the browser automation takes a screenshot
 * of for `placeholder`. Throws `unexpectedRedirect` when the OP redirects back.
 *
 * upstream: AbstractOIDCCRpInitiatedLogout.performRedirectToEndSessionEndpoint (waitForPlaceholders) + the modules'
 * handleHttp throwing TestFailureException for post_logout_redirect
 */
export async function redirectToEndSessionEndpointExpectingNoRedirect(
	op: Op,
	url: string,
	placeholder: string,
	unexpectedRedirect: string,
): Promise<void> {
	redirectingToEndSessionEndpoint(url);
	const done = new AbortController();
	const redirect = op.server.waitFor("post_logout_redirect", htmlResponse(resultCapturedPage(op.testId)), {
		timeoutSeconds: 300,
		signal: done.signal,
	});
	redirect.catch(() => {});
	const visit = op.browser.visit(url, { placeholder });
	visit.catch(() => {});
	try {
		const outcome = await Promise.race([redirect.then(() => "redirect" as const), visit.then(() => "page" as const)]);
		if (outcome === "redirect") {
			throw new Error(unexpectedRedirect);
		}
	} finally {
		done.abort();
	}
}

/**
 * Sends the browser to the end_session_endpoint and waits for both the OP's logout notification (the back-channel
 * logout POST, or the front-channel logout page the OP loads in an iframe) and the redirect to the
 * post_logout_redirect_uri, in either order; logs which one arrived first, as upstream does.
 *
 * upstream: OIDCCBackChannelRpInitiatedLogout / OIDCCFrontChannelRpInitiatedLogout handleBackchannelLogout /
 * handleFrontchannelLogout / handlePostLogoutRedirect
 */
export async function redirectToEndSessionEndpointAndWaitForLogoutRequest(
	op: Op,
	url: string,
	channel: "backchannel" | "frontchannel",
): Promise<{ logoutRequest: IncomingRequest; postLogoutRedirect: IncomingRequest }> {
	redirectingToEndSessionEndpoint(url);
	const waiting =
		channel === "backchannel"
			? {
					redirectFirst: "Received front channel redirect; waiting for back channel request",
					requestFirst: "Received backchannel request; waiting for front channel redirect",
				}
			: {
					redirectFirst: "Received front channel redirect; waiting for front channel request",
					requestFirst: "Received frontchannel request; waiting for front channel redirect",
				};
	let redirected = false;
	let notified = false;
	const [logoutRequest, postLogoutRedirect] = await Promise.all([
		op.server.waitFor(
			channel + "_logout",
			() => {
				notified = true;
				if (!redirected) {
					logModule(waiting.requestFirst);
				}
				// https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse,
				// https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
				return new Response("", { status: 200, headers: { "cache-control": "no-store" } });
			},
			{ timeoutSeconds: 120 },
		),
		op.server.waitFor(
			"post_logout_redirect",
			() => {
				redirected = true;
				if (!notified) {
					logModule(waiting.redirectFirst);
				}
				return htmlResponse(resultCapturedPage(op.testId));
			},
			{ timeoutSeconds: 120 },
		),
		op.browser.visit(url),
	]);
	return { logoutRequest, postLogoutRedirect };
}

// ---- the post logout redirect ----

function queryParam(req: IncomingRequest, name: string): string | null {
	const v = req.query_string_params[name];
	return typeof v === "string" ? v : null;
}

/** upstream: condition/client/CheckPostLogoutState.java */
export function checkPostLogoutState(
	redirect: IncomingRequest,
	expectedState: string,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckPostLogoutState", ...requirements);
	const state = queryParam(redirect, "state");
	if (state == null) {
		c.failure("state not present in query params passed to post logout redirect uri.");
	}
	if (expectedState !== state) {
		c.failure(
			"state in query params passed to post logout redirect uri does not match state passed in the end_session request.",
			{ actual: state, expected: expectedState },
		);
	}
	c.success("state passed to post logout redirect uri matches request");
}

/** upstream: condition/client/CheckNoPostLogoutState.java */
export function checkNoPostLogoutState(redirect: IncomingRequest, ...requirements: string[]): void {
	const c: Condition = condition("CheckNoPostLogoutState", ...requirements);
	if (queryParam(redirect, "state") != null) {
		c.failure("state present in query params passed to post logout redirect uri, but no state was passed to request.");
	}
	c.success("state not passed to post logout redirect uri.");
}

/** upstream: condition/client/CheckForUnexpectedParametersInPostLogoutRedirect.java */
export function checkForUnexpectedParametersInPostLogoutRedirect(
	redirect: IncomingRequest,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckForUnexpectedParametersInPostLogoutRedirect", ...requirements);
	const params = redirect.query_string_params;
	const unexpected = Object.fromEntries(Object.entries(params).filter(([key]) => key !== "state"));
	if (Object.keys(unexpected).length !== 0) {
		c.failure(
			"post_logout_redirect includes unexpected parameters in url query. This may indicate the server has misunderstood the spec, or it may be using extensions the test suite is unaware of.",
			unexpected,
		);
	}
	c.success("post_logout_redirect includes only expected parameters", params);
}

// ---- the back-channel logout request ----

function header(req: IncomingRequest, name: string): string | null {
	const v = req.headers[name];
	return typeof v === "string" ? v : null;
}

/**
 * This is a mixture of must & recommended in BCP195 (upstream reads the x-ssl-* headers its TLS-terminating proxy
 * adds; the suite's server adds them itself).
 *
 * upstream: condition/common/EnsureIncomingTls12WithSecureCipherOrTls13.java
 */
export function ensureIncomingTls12WithSecureCipherOrTls13(req: IncomingRequest, ...requirements: string[]): void {
	const c: Condition = condition("EnsureIncomingTls12WithSecureCipherOrTls13", ...requirements);
	const protocol = header(req, "x-ssl-protocol");
	if (!protocol) {
		c.failure("TLS Protocol not found; this header should have been set by the apache proxy");
	}
	if (protocol === "TLSv1.2") {
		const cipher = header(req, "x-ssl-cipher");
		// the older BCP195 (RFC7525) recommendations, as OpenSSL cipher names
		const recommended = [
			"DHE-RSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"DHE-RSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
		];
		if (!recommended.includes(cipher ?? "")) {
			c.failure("TLS 1.2 in use and cipher is not one recommended by BCP195", {
				expected: recommended,
				actual: cipher,
			});
		}
		c.success("TLS 1.2 in use and cipher is one recommended by BCP195", { recommended, actual: cipher });
		return;
	}
	if (protocol === "TLSv1.3") {
		c.success("Found TLS 1.3 connection");
		return;
	}
	c.failure("TLS version is neither 1.2 nor 1.3", { actual: protocol });
}

/** upstream: condition/common/EnsureIncomingTls13.java */
export function ensureIncomingTls13(req: IncomingRequest, ...requirements: string[]): void {
	const c: Condition = condition("EnsureIncomingTls13", ...requirements);
	const protocol = header(req, "x-ssl-protocol");
	if (!protocol) {
		c.failure("TLS protocol not found; this header should have been set by the nginx proxy");
	}
	if (protocol !== "TLSv1.3") {
		c.failure("Client doesn't support TLS 1.3", { actual: protocol });
	}
	c.success("TLS 1.3 in use");
}

function logoutTokenParam(req: IncomingRequest): unknown {
	return req.body_form_params?.["logout_token"];
}

/**
 * An encrypted logout token must be encrypted to a key the client has.
 *
 * upstream: condition/client/ValidateLogoutTokenFromBackchannelLogoutRequestEncryption.java (AbstractVerifyJweEncryption)
 */
export function validateLogoutTokenFromBackchannelLogoutRequestEncryption(
	req: IncomingRequest,
	clientJwks: unknown,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateLogoutTokenFromBackchannelLogoutRequestEncryption", ...requirements);
	const logoutToken = logoutTokenParam(req);
	if (typeof logoutToken !== "string") {
		c.failure("Couldn't find logout_token in backchannel_logout_request.body_form_params");
	}
	if (token.verifyJweEncryption(c, logoutToken, clientJwks, "logout_token")) {
		c.success("The client has a valid asymmetric key to decrypt the logout token");
	} else {
		c.success("The logout token is not encrypted using an asymmetric encryption algorithm");
	}
}

/** upstream: condition/client/ExtractLogoutTokenFromBackchannelLogoutRequest.java (AbstractExtractJWT) */
export async function extractLogoutTokenFromBackchannelLogoutRequest(
	req: IncomingRequest,
	...requirements: string[]
): Promise<ParsedJwt> {
	const c: Condition = condition("ExtractLogoutTokenFromBackchannelLogoutRequest", ...requirements);
	const where = "backchannel_logout_request";
	const logoutToken = logoutTokenParam(req);
	if (logoutToken == null || typeof logoutToken === "object") {
		c.failure("Couldn't find body_form_params.logout_token in " + where);
	}
	try {
		const parsed = await parseJwt(String(logoutToken));
		if (parsed == null) {
			c.failure("Couldn't parse logout_token from " + where + " as a JWT", { logout_token: logoutToken });
		}
		c.success("Found and parsed the logout_token from " + where, { ...parsed });
		return parsed;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse logout_token from " + where + " as a JWT", e, { logout_token: logoutToken });
		}
		if (e instanceof JOSEException || (e as Error).name?.startsWith("JOSE")) {
			c.failureFrom("Decrypting logout_token from " + where + " failed", e, { logout_token: logoutToken });
		}
		throw e;
	}
}

/** upstream: condition/client/CheckForUnexpectedParametersInBackchannelLogoutRequest.java */
export function checkForUnexpectedParametersInBackchannelLogoutRequest(
	req: IncomingRequest,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckForUnexpectedParametersInBackchannelLogoutRequest", ...requirements);
	const params = req.body_form_params ?? {};
	const unexpected = Object.fromEntries(Object.entries(params).filter(([key]) => key !== "logout_token"));
	if (Object.keys(unexpected).length !== 0) {
		c.failure(
			"backchannel_logout_request includes unexpected parameters. This may indicate the server has misunderstood the spec, or it may be using extensions the test suite is unaware of.",
			unexpected,
		);
	}
	c.success("backchannel_logout_request includes only expected parameters", params);
}

/** upstream: condition/client/ValidateLogoutTokenSignature.java (AbstractVerifyJwsSignature) */
export async function validateLogoutTokenSignature(
	logoutToken: ParsedJwt,
	serverJwks: unknown,
	...requirements: string[]
): Promise<void> {
	const c: Condition = condition("ValidateLogoutTokenSignature", ...requirements);
	await verifyJwsSignature(c, logoutToken.value, serverJwks, "logout_token", false, "server");
}

const DAY_MILLIS = 24 * 60 * 60 * 1000;
/** 5 minute allowable skew for testing */
const TIME_SKEW_MILLIS = 5 * 60 * 1000;

/**
 * iss, aud, iat, jti and events, in the order https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
 * lists them (sub, sid and nonce have their own checks).
 *
 * upstream: condition/client/ValidateLogoutTokenClaims.java
 */
export function validateLogoutTokenClaims(
	logoutToken: ParsedJwt,
	metadata: ServerMetadata,
	client: Client,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateLogoutTokenClaims", ...requirements);
	const clientId = client.client_id;
	const issuer = metadata.issuer;
	const now = Date.now();
	if (!clientId || !issuer) {
		c.failure("Couldn't find values to test token against");
	}
	const claims = logoutToken.claims;
	const iss = claims["iss"];
	if (iss == null) {
		c.failure("'iss' claim missing");
	}
	if (issuer !== iss) {
		c.failure("Issuer mismatch", { expected: issuer, actual: iss });
	}
	const aud = claims["aud"];
	if (aud == null) {
		c.failure("'aud' claim missing");
	}
	if (Array.isArray(aud)) {
		if (!aud.includes(clientId)) {
			c.failure("'aud' array does not contain our client id", { expected: clientId, actual: aud });
		}
	} else if (clientId !== aud) {
		c.failure("'aud' is not our client id", { expected: clientId, actual: aud });
	}
	const iat = typeof claims["iat"] === "number" ? claims["iat"] : null;
	if (iat == null) {
		c.failure("'iat' claim missing");
	}
	if (now + TIME_SKEW_MILLIS < iat * 1000) {
		c.failure("Token 'iat' in the future", { "issued-at": new Date(iat * 1000), now: new Date(now) });
	}
	if (now - DAY_MILLIS > iat * 1000) {
		c.failure("'iat' is more than 1 day in the past", { "issued-at": new Date(iat * 1000), now: new Date(now) });
	}
	if (claims["jti"] == null) {
		c.failure("jti missing");
	}
	const events = claims["events"];
	if (events == null) {
		c.failure("'events' claim missing");
	}
	if (typeof events !== "object" || Array.isArray(events)) {
		c.failure("'events' claim is not a json object");
	}
	const eventsObj = events as Record<string, unknown>;
	if (Object.keys(eventsObj).length !== 1) {
		c.failure("'events' object does not contain exactly 1 entry", eventsObj);
	}
	const logoutEvent = eventsObj["http://schemas.openid.net/event/backchannel-logout"];
	if (logoutEvent === undefined) {
		c.failure("http://schemas.openid.net/event/backchannel-logout entry is missing from 'events' claim", eventsObj);
	}
	if (typeof logoutEvent !== "object" || logoutEvent === null || Array.isArray(logoutEvent)) {
		c.failure("http://schemas.openid.net/event/backchannel-logout is not a json object");
	}
	if (Object.keys(logoutEvent).length !== 0) {
		c.failure("http://schemas.openid.net/event/backchannel-logout is not an empty object", eventsObj);
	}
	c.success("logout token iss, aud, iat, jti and events claims passed validation checks");
}

/** upstream: condition/client/CheckIdTokenSubMatchesLogoutToken.java */
export function checkIdTokenSubMatchesLogoutToken(
	idTokenFromLogin: ParsedJwt,
	logoutToken: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckIdTokenSubMatchesLogoutToken", ...requirements);
	const fields = { id_token: idTokenFromLogin.claims, logout_token: logoutToken.claims };
	// UPSTREAM: Java's subIdToken.equals(...) throws a NullPointerException when the id_token has no sub
	if (idTokenFromLogin.claims["sub"] !== logoutToken.claims["sub"]) {
		c.failure("The id_token and the logout_token contain different sub claims, but must contain the same sub.", fields);
	}
	c.success("sub from the id_token matches that in the logout_token", fields);
}

/** upstream: condition/client/CheckIdTokenSidMatchesLogoutToken.java */
export function checkIdTokenSidMatchesLogoutToken(
	idTokenFromLogin: ParsedJwt,
	logoutToken: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckIdTokenSidMatchesLogoutToken", ...requirements);
	const fields = { id_token: idTokenFromLogin.claims, logout_token: logoutToken.claims };
	// UPSTREAM: Java's sidIdToken.equals(...) throws a NullPointerException when the id_token has no sid
	if (idTokenFromLogin.claims["sid"] !== logoutToken.claims["sid"]) {
		c.failure("The id_token and the logout_token contain different sid claims, but must contain the same sid.", fields);
	}
	c.success("sid in the id_token matches that in the logout_token", fields);
}

/** upstream: condition/client/CheckLogoutTokenNoNonce.java */
export function checkLogoutTokenNoNonce(logoutToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("CheckLogoutTokenNoNonce", ...requirements);
	if (logoutToken.claims["nonce"] != null) {
		c.failure("Logout token has a nonce, which it must not.");
	}
	c.success("No nonce in logout token.");
}

/** upstream: condition/client/CheckLogoutTokenHasSubOrSid.java */
export function checkLogoutTokenHasSubOrSid(logoutToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("CheckLogoutTokenHasSubOrSid", ...requirements);
	if (logoutToken.claims["sub"] == null && logoutToken.claims["sid"] == null) {
		c.failure("logout token has neither sub nor sid - it must have at least one of them.");
	}
	c.success("logout token contains sub and/or sid");
}

// ---- the front-channel logout request ----

/** upstream: condition/client/CheckForUnexpectedParametersInFrontchannelLogoutRequest.java */
export function checkForUnexpectedParametersInFrontchannelLogoutRequest(
	req: IncomingRequest,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckForUnexpectedParametersInFrontchannelLogoutRequest", ...requirements);
	const params = req.query_string_params;
	const unexpected = Object.fromEntries(Object.entries(params).filter(([key]) => key !== "sid" && key !== "iss"));
	if (Object.keys(unexpected).length !== 0) {
		c.failure(
			"frontchannel_logout_request includes unexpected parameters. This may indicate the server has misunderstood the spec, or it may be using extensions the test suite is unaware of.",
			unexpected,
		);
	}
	c.success("frontchannel_logout_request includes only expected parameters", params);
}

/** upstream: condition/client/ValidateFrontchannelLogoutIss.java */
export function validateFrontchannelLogoutIss(
	req: IncomingRequest,
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateFrontchannelLogoutIss", ...requirements);
	const issuer = metadata.issuer;
	const iss = queryParam(req, "iss");
	if (!issuer) {
		c.failure("Couldn't find issuer");
	}
	if (!iss) {
		c.failure("'iss' missing from frontchannel logout request");
	}
	if (issuer !== iss) {
		c.failure("Issuer mismatch", { expected: issuer, actual: iss });
	}
	c.success("'iss' in frontchannel logout request matches server issuer");
}

/** upstream: condition/client/CheckIdTokenSidMatchesFrontChannelLogoutRequest.java */
export function checkIdTokenSidMatchesFrontChannelLogoutRequest(
	idTokenFromLogin: ParsedJwt,
	req: IncomingRequest,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckIdTokenSidMatchesFrontChannelLogoutRequest", ...requirements);
	const sid = queryParam(req, "sid");
	if (!sid) {
		c.failure("'sid' missing from frontchannel logout request");
	}
	const fields = { id_token: idTokenFromLogin.claims, logout_request: req.query_string_params };
	// UPSTREAM: Java's sidIdToken.equals(...) throws a NullPointerException when the id_token has no sid
	if (idTokenFromLogin.claims["sid"] !== sid) {
		c.failure(
			"The id_token and the frontchannel logout request contain different sid claims, but must contain the same sid.",
			fields,
		);
	}
	c.success("sid is the same in the id_token and the front channel logout request", fields);
}

/**
 * Logout at the emulated OP (upstream openid/client/logout/AbstractOIDCCClientLogoutTest.java and its subclasses):
 * the end_session_endpoint the RP sends its user agent to (RP-Initiated Logout), the logout_token the OP posts to
 * the RP's backchannel_logout_uri (Back-Channel Logout), the page that loads the RP's frontchannel_logout_uri in an
 * iframe (Front-Channel Logout), and the redirect to the post_logout_redirect_uri.
 *
 *   const op = await rp.start(logout.logoutTestOptions({ channels: "back", ...the module's changes }));
 *   const client = rp.driveClient();
 *   await op.expect("authorization");
 *   const { backChannelLogoutResponse } = await op.expect("end_session");   // the RP logged out
 *
 * The session the logout ends (session_state, sid) is in src/rp/session.ts.
 */
import { randomUUID } from "node:crypto";
import { block, condition, ConditionFailed, soft, skipped, type Condition } from "../suite/conditions.ts";
import { endpointResponse, HttpError, request, type EndpointResponse } from "../suite/http.ts";
import type { Jwks } from "../suite/jose.ts";
import { escapeHtml } from "../suite/log.ts";
import { htmlResponse, type IncomingRequest } from "../suite/server.ts";
import { parseJWK, selectAsymmetricJWSKey, parseJWKSet, toPublicJWK, type JWK } from "../suite/jose-jwk.ts";
import { JWS_FAMILY_HMAC_SHA } from "../suite/jose-algorithms.ts";
import { toUriString } from "../suite/uri.ts";
import { isJOSEException, ParseException } from "../suite/errors.ts";
import { rsaSigner, ecSigner, macSigner, ed25519Signer } from "../suite/jose-jws.ts";
import { parseClaimsSet } from "../suite/jose-jwt.ts";
import { oidccGenerateServerConfigurationWithSessionManagement } from "./discovery.ts";
import { failTest, type EmulatedOp, type EmulatedOpOptions } from "./op.ts";
import type { RpClient } from "./registration.ts";
import {
	addSessionStateToAuthorizationEndpointResponseParams,
	addSidToIdTokenClaims,
	generateSessionState,
	logoutByRemovingSessionState,
	type LoginSession,
	type SessionStateData,
} from "./session.ts";
import type { UserInfo } from "./userinfo.ts";

/** upstream env "end_session_endpoint_http_request_params" */
export type EndSessionParams = Record<string, unknown>;

/** upstream env "logout_token_claims" */
export type LogoutTokenClaims = Record<string, unknown>;

/**
 * How the OP tells the RP about the logout after the end_session request:
 * - "registered": back-channel and/or front-channel, for each logout URI the client registered (OIDCCClientTestRPInitLogout)
 * - "back": the back-channel logout request (AbstractOIDCCClientBackChannelLogoutTest)
 * - "front": the front-channel logout page (AbstractOIDCCClientFrontChannelLogoutTest)
 * - "none": neither, just the post logout redirect (AbstractOIDCCClientLogoutTest)
 */
export type LogoutChannels = "registered" | "back" | "front" | "none";

/** The logout endpoints' behaviour: upstream AbstractOIDCCClientLogoutTest's overridable methods */
export interface LogoutOptions {
	channels: LogoutChannels;
	/** The login session (upstream "session_state_data"), shared by the authorization and logout endpoints */
	session: LoginSession;
	/** Checks after the standard end_session request checks (upstream validateEndSessionEndpointParameters override) */
	checkEndSessionRequest?: (params: EndSessionParams) => void;
	/** Changes to the post_logout_redirect_uri parameters (upstream customizeEndSessionEndpointResponseParameters) */
	postLogoutRedirectParams?: (params: Record<string, string>) => void;
	/** Changes to the logout_token claims (upstream customizeLogoutTokenClaims) */
	logoutTokenClaims?: (claims: LogoutTokenClaims) => void;
	/** Signs the logout_token instead of OIDCCSignLogoutToken (upstream signLogoutToken) */
	signLogoutToken?: (claims: LogoutTokenClaims, op: EmulatedOp) => string | Promise<string>;
	/**
	 * Checks of the RP's back-channel logout response after the cache headers (upstream
	 * validateBackChannelLogoutResponse override)
	 */
	checkBackChannelLogoutResponse?: (response: EndpointResponse) => void;
}

/** What op.expect("end_session") resolves with */
export interface EndSessionEvent {
	request: IncomingRequest;
	/** upstream "end_session_endpoint_http_request_params" */
	params: EndSessionParams;
	/** upstream "post_logout_redirect_uri_redirect" */
	postLogoutRedirect: string;
	/** The RP's answer to the back-channel logout request (upstream "backchannel_logout_endpoint_response"), if sent */
	backChannelLogoutResponse: EndpointResponse | null;
	/** The frontchannel_logout_uri the front-channel logout page loads (upstream "rp_frontchannel_logout_uri_request_url"), if rendered */
	frontChannelLogoutUrl: string | null;
}

/**
 * The emulated OP of the logout and session management tests (upstream AbstractOIDCCClientLogoutTest): metadata with
 * end_session_endpoint / check_session_iframe and the logout support flags, a session (session_state, sid) created
 * with every authorization request and returned in the authorization response and the id_token, and the logout
 * endpoints with the module's `logout` behaviour.
 */
export function logoutTestOptions(logout: Omit<LogoutOptions, "session">): EmulatedOpOptions {
	const session: LoginSession = { data: null, endSessionRequestReceived: false };
	const sessionData = (): SessionStateData => {
		if (session.data == null) {
			throw new Error("There is no session (session_state_data): the RP sent no authorization request");
		}
		return session.data;
	};
	return {
		serverConfiguration: (baseUrl) =>
			oidccGenerateServerConfigurationWithSessionManagement(
				baseUrl,
				"OIDCBCL-2.1",
				"OIDCSM-3.3",
				"OIDCFCL-3",
				"OIDCRIL-2.1",
			),
		// EnsureMatchingClientId (it stops the test) has made sure the request's client_id is the registered client's
		checkAuthorizationRequest: (params) => {
			session.data = generateSessionState(String(params["client_id"]), params, "OIDCSM-3");
		},
		customizeAuthorizationResponse: (params) =>
			addSessionStateToAuthorizationEndpointResponseParams(params, sessionData(), "OIDCSM-3"),
		customIdTokenClaims: (claims) => addSidToIdTokenClaims(claims, sessionData(), "OIDCFCL-3"),
		logout: { ...logout, session },
	};
}

// ---------------------------------------------------------------------------------------------------------------
// the end_session request

/** upstream: condition/as/logout/EnsureClientHasAtLeastOneOfBackOrFrontChannelLogoutUri.java */
export function ensureClientHasAtLeastOneOfBackOrFrontChannelLogoutUri(
	client: RpClient,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureClientHasAtLeastOneOfBackOrFrontChannelLogoutUri", ...requirements);
	const backChannelLogoutUri = optString(client, "backchannel_logout_uri");
	const frontChannelLogoutUri = optString(client, "frontchannel_logout_uri");
	if (!backChannelLogoutUri && !frontChannelLogoutUri) {
		c.failure("At least one of backchannel_logout_uri or frontchannel_logout_uri is required");
	}
	c.success("Client has either backchannel_logout_uri or frontchannel_logout_uri (or both) set", {
		backchannel_logout_uri: backChannelLogoutUri,
		frontchannel_logout_uri: frontChannelLogoutUri,
	});
}

/** upstream: condition/as/logout/ValidateIdTokenHintInRPInitiatedLogoutRequest.java */
export function validateIdTokenHintInRPInitiatedLogoutRequest(
	params: EndSessionParams,
	issuedIdTokens: string[],
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateIdTokenHintInRPInitiatedLogoutRequest", ...requirements);
	const idTokenHint = optString(params, "id_token_hint");
	if (idTokenHint == null || !issuedIdTokens.includes(idTokenHint)) {
		c.failure("Invalid id_token_hint, not an id_token issued by this test instance.", {
			id_token_hint: idTokenHint,
			issued_id_tokens: issuedIdTokens,
		});
	}
	c.success("id_token_hint was issued by this test instance", { id_token_hint: idTokenHint });
}

/** upstream: condition/as/logout/ValidatePostLogoutRedirectUri.java */
export function validatePostLogoutRedirectUri(
	params: EndSessionParams,
	client: RpClient,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidatePostLogoutRedirectUri", ...requirements);
	if (!("post_logout_redirect_uris" in client)) {
		c.failure("The client does not have any post_logout_redirect_uris");
	}
	const registeredUris = client["post_logout_redirect_uris"];
	const postLogoutRedirectUri = optString(params, "post_logout_redirect_uri");
	if (postLogoutRedirectUri == null) {
		c.failure("no post_logout_redirect_uri passed to end_session_endpoint");
	}
	if (!Array.isArray(registeredUris) || !registeredUris.includes(postLogoutRedirectUri)) {
		c.failure("Invalid post_logout_redirect_uri in request", {
			registered_uris: registeredUris,
			actual: postLogoutRedirectUri,
		});
	}
	c.success("post_logout_redirect_uri is one of the registered post_logout_redirect_uris", {
		post_logout_redirect_uri: postLogoutRedirectUri,
	});
}

/** upstream: condition/as/logout/EnsureEndSessionEndpointRequestContainsStateParameter.java */
export function ensureEndSessionEndpointRequestContainsStateParameter(
	params: EndSessionParams,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureEndSessionEndpointRequestContainsStateParameter", ...requirements);
	const state = optString(params, "state");
	if (state == null || state === "") {
		c.failure("Missing state parameter. end_session_endpoint request must contain a state parameter");
	}
	c.success("end_session_endpoint request contains state parameter", { state });
}

/** upstream: condition/as/logout/CreatePostLogoutRedirectUriParams.java */
export function createPostLogoutRedirectUriParams(
	params: EndSessionParams,
	...requirements: string[]
): Record<string, string> {
	const state = optString(params, "state");
	const responseParams: Record<string, string> = {};
	if (state != null) {
		responseParams["state"] = state;
	}
	condition("CreatePostLogoutRedirectUriParams", ...requirements).log(
		"Added post_logout_redirect_uri parameters to environment",
		{ params: responseParams },
	);
	return responseParams;
}

/** upstream: condition/as/logout/RemoveStateFromPostLogoutRedirectUriParams.java */
export function removeStateFromPostLogoutRedirectUriParams(
	responseParams: Record<string, string>,
	...requirements: string[]
): void {
	const c = condition("RemoveStateFromPostLogoutRedirectUriParams", ...requirements);
	if ("state" in responseParams) {
		delete responseParams["state"];
		c.log("Removed state from end_session_endpoint response parameters", { params: responseParams });
	} else {
		c.log("end_session_endpoint response parameters does not contain a state parameter", { params: responseParams });
	}
}

/** upstream: condition/as/logout/AddInvalidStateToPostLogoutRedirectUriParams.java */
export function addInvalidStateToPostLogoutRedirectUriParams(
	responseParams: Record<string, string>,
	...requirements: string[]
): void {
	// might be better to throw an error assuming that this condition will be used only when state is required? (upstream)
	responseParams["state"] = "state" in responseParams ? responseParams["state"] + "_INVALID" : "INVALID";
	condition("AddInvalidStateToPostLogoutRedirectUriParams", ...requirements).log(
		"Added invalid value for state parameter",
		{ params: responseParams },
	);
}

/** upstream: condition/as/logout/CreatePostLogoutRedirectUriRedirect.java */
export function createPostLogoutRedirectUriRedirect(
	responseParams: Record<string, string>,
	params: EndSessionParams,
	...requirements: string[]
): string {
	const redirectUri = optString(params, "post_logout_redirect_uri") as string;
	const redirectTo = toUriString(redirectUri, Object.entries(responseParams));
	condition("CreatePostLogoutRedirectUriRedirect", ...requirements).success(
		"Created post_logout_redirect_uri redirect",
		{
			uri: redirectTo,
		},
	);
	return redirectTo;
}

// ---------------------------------------------------------------------------------------------------------------
// the logout token

/** upstream: condition/as/logout/GenerateLogoutTokenClaims.java */
export function generateLogoutTokenClaims(
	userInfo: UserInfo,
	issuer: string,
	client: RpClient,
	session: SessionStateData | null,
	...requirements: string[]
): LogoutTokenClaims {
	const claims: LogoutTokenClaims = {
		iss: issuer,
		sub: userInfo["sub"],
		aud: client.client_id,
		jti: randomUUID(),
	};
	if (session?.sid != null) {
		claims["sid"] = session.sid;
	}
	claims["events"] = { "http://schemas.openid.net/event/backchannel-logout": {} };
	const iat = Math.floor(Date.now() / 1000);
	claims["iat"] = iat;
	// OPs are encouraged to use short expiration times in Logout Tokens, preferably at most two minutes in the future
	claims["exp"] = iat + 2 * 60;
	claims["ignored_claim"] =
		"Logout Tokens MAY contain other Claims. Any Claims used that are not understood MUST be ignored.";
	condition("GenerateLogoutTokenClaims", ...requirements).success("Created Logout Token Claims", claims);
	return claims;
}

/** upstream: condition/as/logout/AddInvalidAudValueToLogoutToken.java */
export function addInvalidAudValueToLogoutToken(claims: LogoutTokenClaims, ...requirements: string[]): void {
	const aud = `${String(claims["aud"])}INVALID`;
	claims["aud"] = aud;
	condition("AddInvalidAudValueToLogoutToken", ...requirements).log("Added invalid aud to logout token claims", {
		logout_token_claims: claims,
		aud,
	});
}

/** upstream: condition/as/logout/AddInvalidIssValueToLogoutToken.java */
export function addInvalidIssValueToLogoutToken(claims: LogoutTokenClaims, ...requirements: string[]): void {
	const iss = `${String(claims["iss"])}INVALID`;
	claims["iss"] = iss;
	condition("AddInvalidIssValueToLogoutToken", ...requirements).log("Added invalid iss to logout token claims", {
		logout_token_claims: claims,
		iss,
	});
}

/** upstream: condition/as/logout/AddInvalidEventsClaimToLogoutToken.java */
export function addInvalidEventsClaimToLogoutToken(claims: LogoutTokenClaims, ...requirements: string[]): void {
	delete claims["events"];
	claims["events"] = { "http://schemas.openid.net/event/foobar": {} };
	condition("AddInvalidEventsClaimToLogoutToken", ...requirements).log("Added invalid events claim to logout token", {
		logout_token_claims: claims,
	});
}

/** upstream: condition/as/logout/RemoveEventsClaimFromLogoutToken.java */
export function removeEventsClaimFromLogoutToken(claims: LogoutTokenClaims, ...requirements: string[]): void {
	delete claims["events"];
	condition("RemoveEventsClaimFromLogoutToken", ...requirements).log("Removed events from logout token claims", {
		logout_token_claims: claims,
	});
}

/** upstream: condition/as/logout/AddNonceToLogoutToken.java */
export function addNonceToLogoutToken(claims: LogoutTokenClaims, ...requirements: string[]): void {
	claims["nonce"] = "logout_tokens_must_not_contain_a_nonce";
	condition("AddNonceToLogoutToken", ...requirements).log("Added nonce claim to logout token claims", {
		logout_token_claims: claims,
	});
}

/** The algorithm the logout token is signed with (upstream OIDCCSignLogoutToken.getAlg) */
function logoutTokenAlg(c: Condition, client: RpClient, signingAlgorithm: string | null): string {
	const configured = client["id_token_signed_response_alg"];
	// use the default
	const alg = typeof configured === "string" && configured.length > 0 ? configured : (signingAlgorithm as string);
	if (alg === "none") {
		c.failure("Algorithm 'none' cannot be used for logout tokens");
	}
	return alg;
}

/** The signing key (upstream AbstractSignJWT.selectOrCreateKey: an HMAC key from the client secret for HS*) */
function selectOrCreateKey(c: Condition, serverJwks: Jwks, alg: string, client: RpClient): JWK {
	if (JWS_FAMILY_HMAC_SHA.includes(alg)) {
		if (typeof client["client_secret"] !== "string") {
			throw new Error("getString called on something that is not a string: " + JSON.stringify(client["client_secret"]));
		}
		return parseJWK({
			kty: "oct",
			use: "sig",
			alg,
			k: Buffer.from(client["client_secret"]).toString("base64url"),
		});
	}
	let jwk: JWK | null;
	try {
		jwk = selectAsymmetricJWSKey(alg, parseJWKSet(JSON.stringify(serverJwks)).keys);
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Could not parse jwks. Failed to find a signing key.", e, { jwks: serverJwks, alg });
		}
		throw e;
	}
	if (jwk == null) {
		c.failure("Jwks does not contain a suitable signing key for the selected algorithm", { signing_algorithm: alg });
	}
	return jwk;
}

/** upstream AbstractSignJWT.signJWTUsingKey: the JWS and what logSuccessByJWTType logs */
async function signUsingKey(
	c: Condition,
	claims: LogoutTokenClaims,
	jwk: JWK,
	alg: string,
): Promise<{
	jws: string;
	header: Record<string, unknown>;
	verifiable: { verifiable_jws: string; public_jwk: string | null };
}> {
	try {
		const kty = jwk["kty"];
		const signer =
			kty === "RSA"
				? rsaSigner(jwk)
				: kty === "EC"
					? ecSigner(jwk)
					: kty === "oct"
						? macSigner(jwk)
						: kty === "OKP"
							? ed25519Signer(jwk)
							: null;
		if (signer == null) {
			c.failure("Couldn't create signer from key; kty must be one of 'oct', 'rsa', 'ec'", { jwk: JSON.stringify(jwk) });
		}
		const header: Record<string, unknown> = { alg };
		if (jwk["kid"] != null) {
			header["kid"] = jwk["kid"];
		}
		const jws = await signer.sign(header as never, JSON.stringify(parseClaimsSet(claims as never)));
		const publicJwk = toPublicJWK(jwk);
		return {
			jws,
			header,
			verifiable: { verifiable_jws: jws, public_jwk: publicJwk != null ? JSON.stringify(publicJwk) : null },
		};
	} catch (e) {
		if (e instanceof ConditionFailed) {
			throw e;
		}
		if (e instanceof ParseException) {
			c.failureFrom(e.message, e);
		}
		if (isJOSEException(e)) {
			const cause = (e as Error).cause;
			c.failureFrom(
				"Unable to sign: " + (e as Error).message + (cause instanceof Error ? " (" + cause.message + ")" : ""),
				e,
			);
		}
		throw e;
	}
}

/**
 * Signs the logout token like an id_token: the client's id_token_signed_response_alg (or the OP's default), never
 * none.
 *
 * upstream: condition/as/logout/OIDCCSignLogoutToken.java
 */
export async function oidccSignLogoutToken(
	claims: LogoutTokenClaims,
	serverJwks: Jwks,
	client: RpClient,
	signingAlgorithm: string | null,
	...requirements: string[]
): Promise<string> {
	const c: Condition = condition("OIDCCSignLogoutToken", ...requirements);
	const alg = logoutTokenAlg(c, client, signingAlgorithm);
	const jwk = selectOrCreateKey(c, serverJwks, alg, client);
	const { jws, header, verifiable } = await signUsingKey(c, claims, jwk, alg);
	c.success("Signed the logout token", {
		logout_token: verifiable,
		algorithm: header["alg"],
		key: JSON.stringify(jwk),
	});
	return jws;
}

/** upstream: condition/as/logout/OIDCCSignLogoutTokenWithAlgNone.java */
export function oidccSignLogoutTokenWithAlgNone(claims: LogoutTokenClaims, ...requirements: string[]): string {
	const jws =
		Buffer.from('{"alg":"none"}').toString("base64url") +
		"." +
		Buffer.from(JSON.stringify(claims)).toString("base64url") +
		".";
	condition("OIDCCSignLogoutTokenWithAlgNone", ...requirements).success(
		"Signed the logout token using algorithm 'none'",
		{
			logout_token: jws,
			algorithm: "none",
		},
	);
	return jws;
}

/**
 * Signs the logout token with RS256 when the client expects anything else, else with ES256.
 *
 * upstream: condition/as/logout/OIDCCSignLogoutTokenWithWrongAlgorithm.java
 */
export async function oidccSignLogoutTokenWithWrongAlgorithm(
	claims: LogoutTokenClaims,
	serverJwks: Jwks,
	client: RpClient,
	signingAlgorithm: string | null,
	...requirements: string[]
): Promise<string> {
	const c: Condition = condition("OIDCCSignLogoutTokenWithWrongAlgorithm", ...requirements);
	const configured = client["id_token_signed_response_alg"];
	const expected = typeof configured === "string" && configured.length > 0 ? configured : signingAlgorithm;
	const alg = expected === "RS256" ? "ES256" : "RS256";
	const jwk = selectOrCreateKey(c, serverJwks, alg, client);
	const { jws, header, verifiable } = await signUsingKey(c, claims, jwk, alg);
	c.success("Signed the logout token with a wrong algorithm", {
		logout_token: verifiable,
		algorithm: header["alg"],
		configured_algorithm: logoutTokenAlg(c, client, signingAlgorithm),
		key: JSON.stringify(jwk),
	});
	return jws;
}

/**
 * The logout token: claims, the module's changes, signed (OIDCCSignLogoutToken unless the module signs it), not
 * encrypted (encrypted logout tokens are not supported yet). Undefined when signing failed (a soft failure).
 *
 * upstream: AbstractOIDCCClientLogoutTest.createLogoutToken
 */
async function createLogoutToken(op: EmulatedOp, client: RpClient, logout: LogoutOptions): Promise<string | undefined> {
	return block("Create Logout Token", async () => {
		const claims =
			soft(() => generateLogoutTokenClaims(op.userInfo, op.issuer, client, logout.session.data, "OIDCBCL-2.4")) ?? {};
		logout.logoutTokenClaims?.(claims);
		const token = logout.signLogoutToken
			? await logout.signLogoutToken(claims, op)
			: await soft(() => oidccSignLogoutToken(claims, op.keys.jwks, client, op.signingAlg, "OIDCBCL-2.4"));
		if (client["id_token_encrypted_response_alg"] == null) {
			skipped(
				"EncryptLogoutToken",
				{ element: ["client", "id_token_encrypted_response_alg"] },
				"OIDCBCL-2.4",
				"OIDCC-10.2",
			);
		} else {
			throw new Error("TODO(port): encrypted logout tokens (EncryptLogoutToken)");
		}
		return token;
	});
}

// ---------------------------------------------------------------------------------------------------------------
// back-channel logout

/** upstream: condition/as/logout/EnsureClientHasBackChannelLogoutUri.java */
export function ensureClientHasBackChannelLogoutUri(client: RpClient, ...requirements: string[]): void {
	const c: Condition = condition("EnsureClientHasBackChannelLogoutUri", ...requirements);
	const uri = optString(client, "backchannel_logout_uri");
	if (uri == null || uri === "") {
		c.failure("backchannel_logout_uri is not defined for the client");
	}
	c.success("backchannel_logout_uri is set", { backchannel_logout_uri: uri });
}

/**
 * POSTs the logout_token (and a parameter the RP must ignore) to the RP's backchannel_logout_uri.
 *
 * upstream: condition/as/logout/CallRPBackChannelLogoutEndpoint.java
 */
export async function callRPBackChannelLogoutEndpoint(
	client: RpClient,
	logoutToken: string,
	...requirements: string[]
): Promise<EndpointResponse> {
	const c: Condition = condition("CallRPBackChannelLogoutEndpoint", ...requirements);
	const body = new URLSearchParams();
	body.set("logout_token", logoutToken);
	body.set(
		"ignored_parameter",
		"The POST body MAY contain other values in addition to logout_token. " +
			"Values that are not understood by the implementation MUST be ignored.",
	);
	try {
		const res = await request(c.name, { url: client["backchannel_logout_uri"] as string, method: "POST", body });
		const response = endpointResponse("backchannel logout", res);
		c.success("Called backchannel_logout_uri", { backchannel_logout_endpoint_response: response });
		return response;
	} catch (e) {
		if (e instanceof HttpError) {
			c.failureFrom("RestClientException happened whilst calling logout endpoint", e);
		}
		throw e;
	}
}

/** upstream: condition/AbstractValidateResponseCacheHeaders.java (doesHeaderContainExpectedValue) */
function headerContains(header: unknown, expected: string): boolean {
	if (Array.isArray(header)) {
		return header.some((h) => headerContains(h, expected));
	}
	if (typeof header !== "string" || !header) {
		return false;
	}
	return header.split(",").some((piece) => piece.trim() === expected);
}

/** upstream: condition/as/logout/EnsureBackChannelLogoutEndpointResponseContainsCacheHeaders.java (AbstractValidateResponseCacheHeaders) */
export function ensureBackChannelLogoutEndpointResponseContainsCacheHeaders(
	response: EndpointResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureBackChannelLogoutEndpointResponseContainsCacheHeaders", ...requirements);
	const name = "RP backchannel_logout_uri response";
	const headers = response.headers;
	if (!("cache-control" in headers)) {
		c.failure(name + " does not contain 'cache-control' header", { response_headers: headers });
	}
	const cacheControl = headers["cache-control"];
	if (!headerContains(cacheControl, "no-store")) {
		c.failure("'cache-control' header in " + name + " does not contain expected value.", {
			expected: "no-store",
			actual: cacheControl,
		});
	}
	c.success("'cache-control' header in " + name + " contains expected value.", { cache_control_header: cacheControl });
}

/** upstream: condition/as/logout/EnsureBackChannelLogoutUriResponseStatusCodeIs200.java */
export function ensureBackChannelLogoutUriResponseStatusCodeIs200(
	response: EndpointResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureBackChannelLogoutUriResponseStatusCodeIs200", ...requirements);
	if (response.status !== 200) {
		c.failure("backchannel_logout_uri returned an unexpected http status", { http_status: response.status });
	}
	c.success("backchannel_logout_uri returned the expected http status", { http_status: response.status });
}

/** upstream: condition/as/logout/EnsureBackChannelLogoutUriResponseStatusCodeIs400.java */
export function ensureBackChannelLogoutUriResponseStatusCodeIs400(
	response: EndpointResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureBackChannelLogoutUriResponseStatusCodeIs400", ...requirements);
	if (response.status !== 400) {
		c.failure("backchannel_logout_uri returned an unexpected response", { http_status: response.status });
	}
	c.success("backchannel_logout_uri returned http 400 as expected", { http_status: response.status });
}

/**
 * The back-channel logout request and the checks of the RP's response. Null when the request could not be sent.
 *
 * upstream: AbstractOIDCCClientLogoutTest.sendBackChannelLogoutRequest, validateBackChannelLogoutResponse
 */
async function sendBackChannelLogoutRequest(
	client: RpClient,
	logoutToken: string | undefined,
	logout: LogoutOptions,
): Promise<EndpointResponse | null> {
	return block("Send Back Channel Logout Request", async () => {
		soft(() => ensureClientHasBackChannelLogoutUri(client, "OIDCBCL-2.2"));
		const response = await soft(() => callRPBackChannelLogoutEndpoint(client, logoutToken ?? "", "OIDCBCL-2.5"));
		// UPSTREAM: without a response the checks below fail on the missing environment entry; here they are not run
		if (response == null) {
			return null;
		}
		soft(() => ensureBackChannelLogoutEndpointResponseContainsCacheHeaders(response, "OIDCBCL-2.8"), "warning");
		logout.checkBackChannelLogoutResponse?.(response);
		return response;
	});
}

// ---------------------------------------------------------------------------------------------------------------
// front-channel logout

/** upstream: condition/as/logout/EnsureClientHasFrontChannelLogoutUri.java */
export function ensureClientHasFrontChannelLogoutUri(client: RpClient, ...requirements: string[]): void {
	const c: Condition = condition("EnsureClientHasFrontChannelLogoutUri", ...requirements);
	const uri = optString(client, "frontchannel_logout_uri");
	if (uri == null || uri === "") {
		c.failure("frontchannel_logout_uri is not defined for the client");
	}
	c.success("frontchannel_logout_uri is set", { frontchannel_logout_uri: uri });
}

/**
 * The frontchannel_logout_uri with iss and sid when the client requires them (frontchannel_logout_session_required).
 * The values are not encoded (UriComponentsBuilder.build().toUriString() without encode()); the query goes before
 * any fragment.
 *
 * upstream: condition/as/logout/CreateRPFrontChannelLogoutRequestUrl.java
 */
export function createRPFrontChannelLogoutRequestUrl(
	client: RpClient,
	issuer: string,
	session: SessionStateData | null,
	...requirements: string[]
): string {
	const c: Condition = condition("CreateRPFrontChannelLogoutRequestUrl", ...requirements);
	const frontchannelLogoutUri = optString(client, "frontchannel_logout_uri");
	if (frontchannelLogoutUri == null || frontchannelLogoutUri === "") {
		c.failure("frontchannel_logout_uri is not defined for the client");
	}
	const queryParams: string[] = [];
	if (client["frontchannel_logout_session_required"] === true) {
		const sid = session?.sid ?? null;
		queryParams.push("iss=" + issuer);
		queryParams.push(sid == null ? "sid" : "sid=" + sid);
	}
	let url = frontchannelLogoutUri;
	if (queryParams.length > 0) {
		const hashIndex = url.indexOf("#");
		const fragment = hashIndex === -1 ? "" : url.substring(hashIndex);
		let base = hashIndex === -1 ? url : url.substring(0, hashIndex);
		base += (base.includes("?") ? "&" : "?") + queryParams.join("&");
		url = base + fragment;
	}
	c.log("Created frontchannel_logout_uri request url", { url });
	return url;
}

/**
 * org.apache.commons.text.StringEscapeUtils.escapeEcmaScript: ' " \ / with a backslash, \b \n \t \f \r, and every
 * other char outside 32..0x7f as \\uXXXX (upper case hex, UTF-16 code units).
 */
export function escapeEcmaScript(input: string): string {
	const named: Record<string, string> = { "\b": "\\b", "\n": "\\n", "\t": "\\t", "\f": "\\f", "\r": "\\r" };
	let out = "";
	for (let i = 0; i < input.length; i++) {
		const ch = input.charAt(i);
		const code = input.charCodeAt(i);
		if (ch === "'" || ch === '"' || ch === "\\" || ch === "/") {
			out += "\\" + ch;
		} else if (named[ch] != null) {
			out += named[ch];
		} else if (code < 32 || code > 0x7f) {
			out += "\\u" + code.toString(16).toUpperCase().padStart(4, "0");
		} else {
			out += ch;
		}
	}
	return out;
}

/**
 * The RP-initiated front-channel logout page (upstream templates/oidccFrontChannelLogout.html, RP init): loads the
 * RP's frontchannel_logout_uri in an iframe, tells the suite when it loaded (frontchannel_logout_callback), then
 * redirects to the post_logout_redirect_uri after 5 seconds. Thymeleaf's [[...]] inlining HTML-escapes the values;
 * the frontchannel_logout_uri is JavaScript-escaped first (StringEscapeUtils.escapeEcmaScript).
 */
export function frontChannelLogoutPage(
	rpFrontChannelLogoutUri: string,
	iframeLoadedCallbackUrl: string,
	postLogoutRedirect: string,
): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OIDF Conformance: Check session iframe</title>
    <meta http-equiv="Cache-control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
</head>
<body>
    <h1>OP initiated front channel logout</h1>
    <div>
        RP frontchannel_logout_uri will be loaded below in an iframe
    </div>

    <div id="msgdiv"></div>
    <style>

        iframe{
            width:90%;
            height:400px;
        }
        #msgdiv{
            color:red;
            font-size:1.2em;
        }
    </style>

    <script>
    //RP init
    var iframe = document.createElement('iframe');
    iframe.onload = function(){
        let url = '${escapeHtml(iframeLoadedCallbackUrl)}';
        const urlData = 'loaded=true';

        if (url.indexOf('?') != -1) {
            url = url + '&' + urlData;
        }
        else {
            url = url + '?' + urlData;
        }

        var xhr = new XMLHttpRequest();
        xhr.open('GET', url, true);
        xhr.onload = function () {
            document.getElementById('msgdiv').innerHTML = 'Logout uri loaded and test marked as finished. You will be redirected to post_logout_uri in 5 seconds.';
            setTimeout(function(){window.location.href='${escapeHtml(postLogoutRedirect)}';}, 5000);
        };
        xhr.onerror = function (event) {
            document.getElementById('msgdiv').innerHTML = 'Failed to mark test as finished! Please try again.';
        };
        xhr.send();
    }
    iframe.src = '${escapeHtml(escapeEcmaScript(rpFrontChannelLogoutUri))}';
    document.body.appendChild(iframe);
    </script>

</body>
</html>`;
}

/**
 * The front-channel logout request url (block "Create Front Channel Logout Request") and the page that loads it
 * (block "Render Page With Front Channel Logout Iframe").
 *
 * upstream: AbstractOIDCCClientLogoutTest.createFrontChannelLogoutRequestUrl, createFrontChannelLogoutModelAndView(false)
 */
async function renderFrontChannelLogout(
	op: EmulatedOp,
	client: RpClient,
	session: SessionStateData | null,
	postLogoutRedirect: string,
): Promise<{ url: string; response: Response }> {
	const url = await block("Create Front Channel Logout Request", () => {
		soft(() => ensureClientHasFrontChannelLogoutUri(client, "OIDCFCL-2"));
		return createRPFrontChannelLogoutRequestUrl(client, op.issuer, session, "OIDCFCL-2");
	});
	await block("Render Page With Front Channel Logout Iframe", () => {});
	const page = frontChannelLogoutPage(url, op.baseUrl + "/frontchannel_logout_callback", postLogoutRedirect);
	return { url, response: htmlResponse(page) };
}

/**
 * The front-channel logout page reports that the RP's frontchannel_logout_uri loaded. Upstream marks the test for
 * review (fireTestReviewNeeded: whether the RP really logged out cannot be seen from a cross-origin iframe), which
 * changes the status only.
 *
 * upstream: AbstractOIDCCClientLogoutTest.handleFrontChannelLogoutCallbackHandler
 */
export async function handleFrontChannelLogoutCallback(): Promise<Response> {
	await block("Front Channel Logout Ajax Callback Handler Request", () => {});
	return Response.json({ ok: true });
}

// ---------------------------------------------------------------------------------------------------------------
// the endpoint

/** The end_session request parameters: the query of a GET, the form of a POST (the spec allows both) */
function endSessionRequestParams(req: IncomingRequest): EndSessionParams {
	if (req.method === "POST") {
		return req.body_form_params ?? {};
	}
	if (req.method === "GET") {
		return req.query_string_params;
	}
	// this should not happen?
	return failTest("Got unexpected HTTP method to end session endpoint");
}

/**
 * The RP sends its user agent to the end_session_endpoint (RP-Initiated Logout). The OP creates the logout token
 * (back-channel), checks the request (id_token_hint, post_logout_redirect_uri, the module's checks), answers with
 * the redirect to the post_logout_redirect_uri or the front-channel logout page, ends the session, and then posts
 * the logout token to the RP's backchannel_logout_uri, as `logout.channels` says.
 *
 * upstream: AbstractOIDCCClientLogoutTest.handleEndSessionEndpointRequest, with the overrides of
 * OIDCCClientTestRPInitLogout ("registered"), AbstractOIDCCClientBackChannelLogoutTest ("back") and
 * AbstractOIDCCClientFrontChannelLogoutTest ("front")
 */
export async function handleEndSessionRequest(
	op: EmulatedOp,
	req: IncomingRequest,
	logout: LogoutOptions,
): Promise<{ response: Response; event: Omit<EndSessionEvent, "request"> }> {
	const client = op.client;
	if (client == null) {
		throw new Error("The RP sent an end_session request before it registered a client");
	}
	const session = logout.session;
	session.endSessionRequestReceived = true;
	let backChannel = logout.channels === "back";
	let frontChannel = logout.channels === "front";
	if (logout.channels === "registered") {
		ensureClientHasAtLeastOneOfBackOrFrontChannelLogoutUri(client);
		frontChannel = !!optString(client, "frontchannel_logout_uri");
		backChannel = !!optString(client, "backchannel_logout_uri");
	}
	// this must be created before the session is actually removed
	const logoutToken = backChannel ? await createLogoutToken(op, client, logout) : undefined;

	const result = await block("End session endpoint", async () => {
		const params = endSessionRequestParams(req);
		soft(() => validateIdTokenHintInRPInitiatedLogoutRequest(params, op.issuedIdTokens, "OIDCRIL-2"));
		soft(() => validatePostLogoutRedirectUri(params, client, "OIDCRIL-3.1"));
		logout.checkEndSessionRequest?.(params);

		const redirectParams = createPostLogoutRedirectUriParams(params, "OIDCRIL-3");
		logout.postLogoutRedirectParams?.(redirectParams);
		const postLogoutRedirect = createPostLogoutRedirectUriRedirect(redirectParams, params, "OIDCRIL-3");

		const front = frontChannel ? await renderFrontChannelLogout(op, client, session.data, postLogoutRedirect) : null;
		const response = front?.response ?? new Response(null, { status: 302, headers: { location: postLogoutRedirect } });
		logoutByRemovingSessionState(session);
		return { params, postLogoutRedirect, response, frontChannelLogoutUrl: front?.url ?? null };
	});

	const backChannelLogoutResponse = backChannel
		? await sendBackChannelLogoutRequest(client, logoutToken, logout)
		: null;
	return {
		response: result.response,
		event: {
			params: result.params,
			postLogoutRedirect: result.postLogoutRedirect,
			backChannelLogoutResponse,
			frontChannelLogoutUrl: result.frontChannelLogoutUrl,
		},
	};
}

/** A string member (OIDFJSON.getString): null when absent, an error when it is not a string */
function optString(o: Record<string, unknown>, name: string): string | null {
	const v = o[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

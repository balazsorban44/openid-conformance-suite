/**
 * The emulated OP's token endpoint: the client authentication and code exchange checks upstream runs on the RP's
 * token request, and the token response (access token, id_token).
 */
import { createHash } from "node:crypto";
import { shannonEntropy } from "../op/authorization.ts";
import { block, condition, soft, type Condition } from "../suite/conditions.ts";
import { currentLog } from "../suite/log.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import type { IncomingRequest } from "../suite/server.ts";
import { calculateAtHash, createIdToken, createIdTokenForRefreshRequest, toUsAscii } from "./id-token.ts";
import { failTest, OAuthError, type EmulatedOp, type RefreshOptions } from "./op.ts";
import { generateVSChar, type RpClient } from "./registration.ts";

/** The access token the OP issued (upstream env "access_token", "token_type", "at_hash") */
export interface IssuedTokens {
	accessToken: string;
	/** "Bearer", or "DPoP" at the FAPI 2 authorization server */
	tokenType: string;
	/** null when the id_token is not signed (alg none) */
	atHash: string | null;
}

/** upstream env "client_authentication" */
export interface ClientAuthentication {
	client_id: string;
	client_secret: string;
	method: string;
}

/** A form parameter read as a string (OIDFJSON.getString): null when absent, an error when repeated */
function formParam(req: IncomingRequest, name: string): string | null {
	const v = req.body_form_params?.[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

/** upstream: condition/as/CheckClientIdMatchesOnTokenRequestIfPresent.java */
export function checkClientIdMatchesOnTokenRequestIfPresent(
	req: IncomingRequest,
	client: RpClient,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckClientIdMatchesOnTokenRequestIfPresent", ...requirements);
	const clientId = formParam(req, "client_id");
	if (!clientId) {
		c.log("client_id not present, nothing to check");
		return;
	}
	if (client.client_id === clientId) {
		c.success("Extracted client_id matches the expected value", { client_id: clientId });
		return;
	}
	c.failure(`client_id on the request ${clientId} does not match the expected one ${client.client_id}`, {
		expected: client.client_id,
		actual: clientId,
	});
}

/** Java URLDecoder.decode: form decoding, '+' is a space */
function formDecode(s: string): string {
	return decodeURIComponent(s.replace(/\+/g, " "));
}

/** upstream: condition/as/ExtractClientCredentialsFromBasicAuthorizationHeader.java */
export function extractClientCredentialsFromBasicAuthorizationHeader(
	req: IncomingRequest,
	...requirements: string[]
): ClientAuthentication {
	const c: Condition = condition("ExtractClientCredentialsFromBasicAuthorizationHeader", ...requirements);
	const auth = req.headers["authorization"];
	if (!auth || typeof auth !== "string") {
		c.failure(
			"This test expected the client to perform client_secret_basic client authorization, but the incoming http request does not contain an authorization header",
		);
	}
	if (!auth.toLowerCase().startsWith("basic")) {
		c.failure("Not a basic authorization header", { auth });
	}
	const encoded = auth.substring("Basic ".length);
	if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
		// Java: Base64.getDecoder().decode() throws IllegalArgumentException
		throw new Error("Illegal base64 character");
	}
	const parts = Buffer.from(encoded, "base64").toString("utf8").split(":");
	if (parts.length !== 2) {
		c.failure("Unexpected number of parts to authorization header", { basic_auth: parts });
	}
	const authentication: ClientAuthentication = {
		client_id: formDecode(parts[0]),
		client_secret: formDecode(parts[1]),
		method: "client_secret_basic",
	};
	c.success("Extracted client authentication", { ...authentication });
	return authentication;
}

/** upstream: condition/as/ExtractClientCredentialsFromFormPost.java */
export function extractClientCredentialsFromFormPost(
	req: IncomingRequest,
	...requirements: string[]
): ClientAuthentication {
	const c: Condition = condition("ExtractClientCredentialsFromFormPost", ...requirements);
	const clientId = formParam(req, "client_id");
	const clientSecret = formParam(req, "client_secret");
	if (!clientId || !clientSecret) {
		c.failure("Couldn't find client credentials in form post");
	}
	const authentication: ClientAuthentication = {
		client_id: clientId,
		client_secret: clientSecret,
		method: "client_secret_post",
	};
	c.success("Extracted client authentication", { ...authentication });
	return authentication;
}

/** upstream: condition/as/ValidateClientIdAndSecret.java */
export function validateClientIdAndSecret(
	authentication: ClientAuthentication,
	client: RpClient,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateClientIdAndSecret", ...requirements);
	if (!authentication.client_id) {
		c.failure("Couldn't find client id in request", { client_authentication: authentication });
	}
	if (client.client_id === authentication.client_id && client["client_secret"] === authentication.client_secret) {
		c.success("Client id and secret match");
		return;
	}
	c.failure("Client authentication failed", {
		expected_client_id: client.client_id,
		received_client_id: authentication.client_id,
		expected_client_secret: client["client_secret"],
		received_client_secret: authentication.client_secret,
	});
}

/**
 * The client authenticates with the variant's method.
 *
 * upstream: sequence/as/OIDCCValidateClientAuthenticationWithClientSecretBasic.java,
 * OIDCCValidateClientAuthenticationWithClientSecretPost.java, OIDCCValidateClientAuthenticationWithNone.java
 */
export function validateClientAuthentication(
	req: IncomingRequest,
	client: RpClient,
	clientAuthType: string,
	/** opUnderTest: a failed authentication rejects the request (upstream's RP test records it and goes on) */
	strict = false,
): void {
	const check = strict ? <T>(fn: () => T) => fn() : soft;
	if (clientAuthType === "client_secret_basic") {
		const authentication = extractClientCredentialsFromBasicAuthorizationHeader(req, "OIDCC-9");
		check(() => validateClientIdAndSecret(authentication, client, "RFC6749-2.3.1"));
	} else if (clientAuthType === "client_secret_post") {
		const authentication = check(() => extractClientCredentialsFromFormPost(req, "OIDCC-9"));
		if (authentication != null) {
			check(() => validateClientIdAndSecret(authentication, client, "RFC6749-2.3.1"));
		}
	} else if (clientAuthType !== "none") {
		// "none": upstream does not check anything (yet)
		throw new Error(`TODO(port): client_auth_type=${clientAuthType} is not supported by the emulated OP yet`);
	}
}

/**
 * The client a token request names: in its Basic authorization header (form-urlencoded, RFC 6749 2.3.1: a '+' is
 * a space), else its client_id parameter (opUnderTest)
 */
export function clientIdOfTokenRequest(req: IncomingRequest): string | null {
	const auth = req.headers["authorization"];
	if (typeof auth === "string" && auth.toLowerCase().startsWith("basic ")) {
		const user = Buffer.from(auth.substring("Basic ".length), "base64").toString("utf8").split(":")[0];
		try {
			return formDecode(user);
		} catch {
			return user;
		}
	}
	return formParam(req, "client_id");
}

/** upstream: condition/as/ValidateAuthorizationCode.java */
export function validateAuthorizationCode(
	req: IncomingRequest,
	expected: string | null,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateAuthorizationCode", ...requirements);
	const actual = formParam(req, "code");
	if (!expected) {
		c.failure("Couldn't find authorization code to compare");
	}
	if (expected !== actual) {
		c.failure("Didn't find matching authorization code", { expected, actual });
	}
	c.success("Found authorization code", { authorization_code: actual });
}

/** upstream: condition/as/ValidateRedirectUriForTokenEndpointRequest.java */
export function validateRedirectUriForTokenEndpointRequest(
	req: IncomingRequest,
	expected: string | undefined,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateRedirectUriForTokenEndpointRequest", ...requirements);
	const actual = formParam(req, "redirect_uri");
	if (!actual) {
		// OIDC 3.1.3.2 allows the OP to proceed when only one redirect_uri is registered; upstream requires it
		c.failure("redirect_uri is missing or empty", { token_endpoint_request: req });
	}
	if (actual !== expected) {
		c.failure("redirect_uri is not equal to the one used in the authorization request", { actual, expected });
	}
	c.success("redirect_uri is the same as the one used in the authorization request", { actual });
}

/** upstream: condition/as/GenerateBearerAccessToken.java */
export function generateBearerAccessToken(): string {
	const accessToken = randomAlphanumeric(50);
	condition("GenerateBearerAccessToken").success("Generated access token", { access_token: accessToken });
	return accessToken;
}

/**
 * Issues the access token (and its at_hash unless the id_token is unsigned).
 *
 * upstream: AbstractOIDCCClientTest.generateAccessToken
 */
export function generateAccessToken(op: EmulatedOp): IssuedTokens {
	const accessToken = generateBearerAccessToken();
	const atHash =
		op.signingAlg !== "none" ? calculateAtHash(accessToken, op.signingAlg as string, "OIDCC-3.3.2.11") : null;
	op.tokens = { accessToken, tokenType: "Bearer", atHash };
	return op.tokens;
}

/**
 * `headers`: the response headers (upstream "token_endpoint_response_headers": x-fapi-interaction-id when known).
 *
 * upstream: condition/as/CreateTokenEndpointResponse.java
 */
export function createTokenEndpointResponse(
	tokens: IssuedTokens,
	idToken: string | null,
	scope: string | null,
	refreshToken: string | null = null,
	expiresIn: number | null = null,
	headers: Record<string, string> = {},
	...requirements: string[]
): Record<string, unknown> {
	const response: Record<string, unknown> = { access_token: tokens.accessToken, token_type: tokens.tokenType };
	if (idToken) {
		response["id_token"] = idToken;
	}
	if (refreshToken) {
		response["refresh_token"] = refreshToken;
	}
	if (scope) {
		response["scope"] = scope;
	}
	if (expiresIn != null) {
		response["expires_in"] = expiresIn;
	}
	// upstream logs the response without a message (logSuccess(args(...)))
	currentLog().log("CreateTokenEndpointResponse", {
		"Created token endpoint response": response,
		token_endpoint_response_headers: headers,
		result: "SUCCESS",
		...(requirements.length > 0 ? { requirements } : {}),
	});
	return response;
}

/**
 * The RP's token request: grant_type, client_id and client authentication, then for authorization_code: the code
 * and redirect_uri of the authorization request, a new access token and id_token. `onCodeExchange` (the module's
 * hook, upstream's authorizationCodeGrantType override) runs before the code is checked.
 *
 * upstream: AbstractOIDCCClientTest.handleTokenEndpointRequest, authorizationCodeGrantType
 */
export async function handleTokenRequest(
	op: EmulatedOp,
	req: IncomingRequest,
): Promise<{ response: Response; tokens: Record<string, unknown> }> {
	const grantType = formParam(req, "grant_type");
	if (grantType == null) {
		failTest("Token endpoint body does not contain the mandatory 'grant_type' parameter");
	}
	return block(grantType === "refresh_token" ? "Token endpoint - Refresh Request" : "Token endpoint", async () => {
		if (op.options.opUnderTest) {
			op.selectClient({ clientId: clientIdOfTokenRequest(req) });
		}
		const client = op.client;
		if (client == null) {
			throw new Error("The RP sent a token request before it registered a client");
		}
		soft(() => checkClientIdMatchesOnTokenRequestIfPresent(req, client, "RFC6749-3.2.1"));
		validateClientAuthentication(req, client, op.clientAuthType, op.options.opUnderTest);
		if (grantType === "refresh_token") {
			if (!op.options.refresh) {
				failTest("refresh_token grant type is not implemented for this test");
			}
			return refreshTokenGrant(op, req, op.options.refresh);
		}
		if (grantType !== "authorization_code") {
			failTest("Got a grant type on the token endpoint we didn't understand: " + grantType);
		}
		op.options.onCodeExchange?.();
		const code = formParam(req, "code");
		if (op.options.opUnderTest && code != null && op.usedCodes.has(code)) {
			// an authorization code is exchanged once; reusing it revokes what it was exchanged for (RFC 6749 4.1.2)
			op.tokens = null;
			op.refreshToken = null;
			throw new OAuthError("invalid_grant", "The authorization code was already used");
		}
		validateAuthorizationCode(req, op.authorization?.code ?? null, "OIDCC-3.1.3.2");
		if (op.options.opUnderTest && code != null) {
			op.usedCodes.add(code);
		}
		soft(() => validateRedirectUriForTokenEndpointRequest(req, op.authorization?.redirectUri, "OIDCC-3.1.3.2"));
		// UPSTREAM: CheckPkceCodeVerifier runs only when the environment has an object "code_challenge", which it never
		// has (EnsureAuthorizationRequestContainsPkceCodeChallenge stores a string): the code_verifier is not checked
		const tokens = generateAccessToken(op);
		const idToken = await createIdToken(op, true);
		if (op.options.refresh) {
			createRefreshToken(op, "RFC6749-1.5");
		}
		const response = createTokenEndpointResponse(
			tokens,
			idToken,
			op.authorization?.scope ?? null,
			op.refreshToken,
			accessTokenExpiration(op),
			{},
			"OIDCC-3.1.3.3",
		);
		return { response: tokenResponse(op, response), tokens: response };
	});
}

/** upstream "access_token_expiration": never set by the RP tests; an OP under test says expires_in */
function accessTokenExpiration(op: EmulatedOp): number | null {
	return op.options.opUnderTest ? 3600 : null;
}

/** The token response; an OP under test adds the cache headers OIDCC-3.1.3.3 requires (upstream sends none) */
function tokenResponse(op: EmulatedOp, body: Record<string, unknown>): Response {
	return Response.json(
		body,
		op.options.opUnderTest ? { headers: { "cache-control": "no-store", pragma: "no-cache" } } : undefined,
	);
}

/**
 * The refresh_token grant (inside the "Token endpoint - Refresh Request" block, client authenticated): the
 * refresh token and scope are checked, a new access token (and id_token, refresh token as the module says) issued.
 * Userinfo requests the RP made before do not count (upstream receivedUserinfoRequest = false: discarded here).
 *
 * upstream: AbstractOIDCCClientTestRefreshToken.refreshTokenGrantType
 */
async function refreshTokenGrant(
	op: EmulatedOp,
	req: IncomingRequest,
	refresh: RefreshOptions,
): Promise<{ response: Response; tokens: Record<string, unknown> }> {
	op.receivedRefreshRequest = true;
	op.discardEvents("userinfo");
	// validateRefreshRequest: the scope check must run before ExtractScopeFromTokenEndpointRequest
	ensureScopeInRefreshRequestContainsNoMoreThanOriginallyGranted(req, op.authorization?.scope ?? null, "RFC6749-6");
	validateRefreshToken(req, op.refreshToken, "RFC6749-6");
	const scope = extractScopeFromTokenEndpointRequest(req);
	if (scope != null && op.authorization != null) {
		op.authorization.scope = scope;
	}
	const tokens = generateAccessToken(op);
	const idToken = refresh.idToken === false ? null : await createIdTokenForRefreshRequest(op, refresh);
	if (refresh.newRefreshToken !== false) {
		createRefreshToken(op, "RFC6749-1.5");
	}
	const response = createTokenEndpointResponse(
		tokens,
		idToken,
		op.authorization?.scope ?? null,
		op.refreshToken,
		accessTokenExpiration(op),
	);
	return { response: tokenResponse(op, response), tokens: response };
}

/** upstream: condition/as/CreateRefreshToken.java */
export function createRefreshToken(op: { refreshToken: string | null }, ...requirements: string[]): string {
	const refreshToken = generateVSChar(50, 10, 5);
	op.refreshToken = refreshToken;
	condition("CreateRefreshToken", ...requirements).log("Created refresh token", { refresh_token: refreshToken });
	return refreshToken;
}

/** upstream: condition/as/ValidateRefreshToken.java */
export function validateRefreshToken(req: IncomingRequest, expected: string | null, ...requirements: string[]): void {
	const c: Condition = condition("ValidateRefreshToken", ...requirements);
	const actual = formParam(req, "refresh_token");
	if (actual == null) {
		c.failure("Request does not contain a refresh_token parameter", { form_parameters: req.body_form_params });
	}
	if (actual !== expected) {
		c.failure("Invalid refresh_token parameter.", { expected, actual });
	}
	c.success("refresh_token parameter matches the expected value.", { refresh_token: actual });
}

/** upstream: condition/as/EnsureScopeInRefreshRequestContainsNoMoreThanOriginallyGranted.java */
export function ensureScopeInRefreshRequestContainsNoMoreThanOriginallyGranted(
	req: IncomingRequest,
	grantedScope: string | null,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureScopeInRefreshRequestContainsNoMoreThanOriginallyGranted", ...requirements);
	const requestedScope = formParam(req, "scope");
	if (requestedScope == null) {
		c.success("Refresh request does not contain scope parameter and is assumed to be the same as originally granted.");
		return;
	}
	const granted = new Set((grantedScope ?? "").split(" "));
	for (const scope of new Set(requestedScope.split(" "))) {
		if (!granted.has(scope)) {
			c.failure("Scope value in refresh request contains a scope that was not originally granted.", {
				originally_granted: grantedScope,
				requested_scopes: requestedScope,
				scope,
			});
		}
	}
	c.success("Scope value in refresh request matches the originally granted scope.", {
		originally_granted: grantedScope,
		requested: requestedScope,
	});
}

/**
 * The scope of a refresh request, which replaces the granted one; null (the granted scope stays) when absent.
 * upstream: condition/as/ExtractScopeFromTokenEndpointRequest.java
 */
export function extractScopeFromTokenEndpointRequest(req: IncomingRequest): string | null {
	const c: Condition = condition("ExtractScopeFromTokenEndpointRequest");
	const scope = formParam(req, "scope");
	if (!scope) {
		c.log("Token endpoint request does not contain a scope parameter");
		return null;
	}
	c.log("Scopes requested in refresh request", { scope });
	return scope;
}

// ---------------------------------------------------------------------------------------------------------------
// the FAPI 2 authorization server's token endpoint (upstream AbstractFAPI2SPFinalClientTest.authorizationCodeGrantType)

/** upstream: condition/as/ValidateRedirectUri.java */
export function validateRedirectUri(
	req: IncomingRequest,
	client: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateRedirectUri", ...requirements);
	const expected = typeof client["redirect_uri"] === "string" ? client["redirect_uri"] : null;
	const actual = formParam(req, "redirect_uri");
	if (!expected) {
		c.failure("Couldn't find redirect uri to compare");
	}
	if (expected === actual) {
		c.success("Found redirect uri", { redirect_uri: actual });
		return;
	}
	c.failure("Didn't find matching redirect uri", { expected, actual });
}

/** The PKCE values of the authorization request (upstream "code_challenge" / "code_challenge_method") */
export interface CodeChallenge {
	code_challenge: string;
	code_challenge_method: string;
}

/** upstream: condition/as/ValidateCodeVerifierWithS256.java */
export function validateCodeVerifierWithS256(
	req: IncomingRequest,
	challenge: CodeChallenge,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateCodeVerifierWithS256", ...requirements);
	const codeVerifier = formParam(req, "code_verifier");
	if (!codeVerifier) {
		c.failure("Couldn't find code_verifier in token request");
	}
	const { code_challenge: codeChallenge, code_challenge_method: codeChallengeMethod } = challenge;
	if (codeChallengeMethod !== "S256") {
		c.failure("Unexpected code_challenge_method", { code_challenge_method: codeChallengeMethod });
	}
	const calculatedChallenge = createHash("sha256")
		.update(Buffer.from(toUsAscii(codeVerifier), "latin1"))
		.digest()
		.toString("base64url");
	if (codeChallenge === calculatedChallenge) {
		c.success("Validated code_verifier successfully", {
			code_verifier: codeVerifier,
			code_challenge: codeChallenge,
			code_challenge_method: codeChallengeMethod,
		});
		return;
	}
	c.failure("PKCE validation failed", {
		expected_code_challenge: calculatedChallenge,
		code_verifier: codeVerifier,
		code_challenge: codeChallenge,
		code_challenge_method: codeChallengeMethod,
	});
}

/**
 * RFC 7636 7.1 asks for 256 bits of entropy; it cannot be measured accurately, so 180 are required.
 *
 * upstream: condition/client/EnsureMinimumPkceCodeVerifierEntropy.java (AbstractEnsureMinimumEntropy)
 */
export function ensureMinimumPkceCodeVerifierEntropy(req: IncomingRequest, ...requirements: string[]): void {
	const c: Condition = condition("EnsureMinimumPkceCodeVerifierEntropy", ...requirements);
	const requiredEntropy = 180;
	const codeVerifier = formParam(req, "code_verifier");
	if (!codeVerifier) {
		c.failure("Couldn't find code_verifier in token request");
	}
	const entropy = shannonEntropy(codeVerifier) * codeVerifier.length;
	const fields = { value: codeVerifier, expected: requiredEntropy, actual: entropy };
	if (entropy <= requiredEntropy) {
		c.failure(
			"Calculated shannon entropy does not seem to meet minimum required entropy (i.e. item is too short, or not random enough)",
			fields,
		);
	}
	c.success("Calculated shannon entropy seems sufficient", fields);
}

/** upstream: condition/client/EnsureMinimumPkceCodeVerifierLength.java */
export function ensureMinimumPkceCodeVerifierLength(req: IncomingRequest, ...requirements: string[]): void {
	const c: Condition = condition("EnsureMinimumPkceCodeVerifierLength", ...requirements);
	// 43 * 8: at least 43 characters (RFC 7636 7.3)
	const requiredLength = 344;
	const codeVerifier = formParam(req, "code_verifier");
	if (!codeVerifier) {
		c.failure("Couldn't find code_verifier in token request");
	}
	const bitLength = Buffer.byteLength(codeVerifier, "utf8") * 8;
	if (bitLength >= requiredLength) {
		c.success("PKCE code verifier is of sufficient length", { required: requiredLength, actual: bitLength });
		return;
	}
	c.failure("PKCE code verifier is not of sufficient length", { required: requiredLength, actual: bitLength });
}

/**
 * `used`: the code verifiers already presented (upstream keeps a process-wide cache of 256; this one is per test).
 *
 * upstream: condition/client/EnsurePkceCodeVerifierNotUsed.java
 */
export function ensurePkceCodeVerifierNotUsed(
	req: IncomingRequest,
	used: Set<string>,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsurePkceCodeVerifierNotUsed", ...requirements);
	const codeVerifier = formParam(req, "code_verifier");
	if (!codeVerifier) {
		c.failure("Code Verifier not found in request");
	}
	if (used.has(codeVerifier)) {
		c.failure("code verifier has been used", { "code verifier": codeVerifier });
	}
	used.add(codeVerifier);
	c.success("Code verifier has not been used", { code_verifier: codeVerifier });
}

/**
 * The code_verifier of the token request matches the code_challenge of the authorization request, is long and
 * random enough, and was not presented before.
 *
 * upstream: condition/as/CheckPkceCodeVerifier.java with condition/as/ValidateCodeVerifierWithS256.java,
 * condition/client/EnsureMinimumPkceCodeVerifierEntropy.java, EnsureMinimumPkceCodeVerifierLength.java,
 * EnsurePkceCodeVerifierNotUsed.java
 */
export function checkPkceCodeVerifier(req: IncomingRequest, challenge: CodeChallenge, used: Set<string>): void {
	validateCodeVerifierWithS256(req, challenge, "RFC7636-4.6");
	soft(() => ensureMinimumPkceCodeVerifierEntropy(req, "RFC7636-7.1"), "warning");
	soft(() => ensureMinimumPkceCodeVerifierLength(req, "RFC7636-7.1"), "warning");
	soft(() => ensurePkceCodeVerifierNotUsed(req, used, "RFC7636-4.1"));
}

/** The expires_in of the token response (upstream "access_token_expiration"). upstream: condition/as/GenerateAccessTokenExpiration.java */
export function generateAccessTokenExpiration(): string {
	condition("GenerateAccessTokenExpiration").log("Set access_token_expiration to 900");
	return "900";
}

/** upstream: condition/as/RemoveAccessTokenExpiration.java */
export function removeAccessTokenExpiration(): void {
	condition("RemoveAccessTokenExpiration").log("Removed access_token_expiration");
}

/** The token_type with every letter's case inverted ("DPoP" -> "dpOp"). upstream: condition/as/SetTokenResponseTokenTypeToInvertedCase.java */
export function setTokenResponseTokenTypeToInvertedCase(tokenType: string | null): string {
	const c: Condition = condition("SetTokenResponseTokenTypeToInvertedCase");
	if (!tokenType) {
		c.failure("token_type not available");
	}
	const inverted = Array.from(tokenType, (ch) =>
		/\p{Alphabetic}/u.test(ch) ? (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()) : ch,
	).join("");
	c.success("Set token endpoint response 'token_type' to inverted case letters", { token_type: inverted });
	return inverted;
}

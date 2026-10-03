/**
 * The refresh token grant: a refresh request with the variant's client authentication, the checks on its response
 * (a new access token, maybe an id_token and refresh token) and the request a client must not be able to make with
 * another client's refresh token.
 *
 *   const refreshed = await block("Refresh Token Request", () =>
 *     refresh.refreshTokenRequestSteps(op, client, refreshToken, first));
 */
import { condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import type { ParsedJwt } from "../suite/jose.ts";
import { waitForOneSecond } from "../suite/wait.ts";
import { shannonEntropy } from "./authorization.ts";
import { compareIdTokenClaims } from "./id-token.ts";
import type { Op } from "./op.ts";
import type { Client, RegisteredClient } from "./registration.ts";
import {
	addClientAuthentication,
	callTokenEndpoint,
	checkErrorFromTokenEndpointResponseErrorInvalidGrant,
	checkIfTokenEndpointResponseError,
	checkTokenEndpointHttpStatus200,
	checkTokenEndpointHttpStatus400,
	checkTokenEndpointReturnedJsonContentType,
	extractAccessTokenFromTokenResponse,
	extractExpiresInFromTokenEndpointResponse,
	extractIdTokenFromTokenResponse,
	validateErrorFromTokenEndpointResponseError,
	validateExpiresIn,
	validateIdTokenFromTokenResponseEncryption,
	type AccessToken,
	type TokenRequest,
	type TokenResponse,
} from "./token.ts";

/** What a refresh request returns (a refresh token is optional: the old one stays valid when none is returned) */
export interface RefreshedTokens {
	accessToken: AccessToken;
	/** undefined when the response had no (parseable) id_token */
	idToken: ParsedJwt | undefined;
	refreshToken: string;
}

function str(o: Record<string, unknown> | null, key: string): string | null {
	const v = o?.[key];
	return typeof v === "string" ? v : null;
}

/** upstream: condition/client/CreateRefreshTokenRequest.java */
export function createRefreshTokenRequest(refreshToken: string): TokenRequest {
	const form = { grant_type: "refresh_token", refresh_token: refreshToken };
	// the headers start empty, so that this is truly a 'new' request
	condition("CreateRefreshTokenRequest").success("Created token endpoint request parameters", { ...form });
	return { form, headers: {} };
}

/**
 * The scope of the refresh request (RFC6749-6): the scope the OP granted when the suite recorded one, else the
 * client's configured scope.
 *
 * upstream: condition/client/AddScopeToTokenEndpointRequest.java
 */
export function addScopeToTokenEndpointRequest(req: TokenRequest, client: Client, ...requirements: string[]): void {
	const c: Condition = condition("AddScopeToTokenEndpointRequest", ...requirements);
	// granted_scope is only recorded by ExtractGrantedScopeFromTokenEndpointResponse, which the OIDCC modules do not call
	let scope = typeof client["granted_scope"] === "string" ? client["granted_scope"] : null;
	let source = "granted by the authorization server";
	if (!scope) {
		scope = client.scope ?? null;
		source = "configured for the client";
	}
	if (!scope) {
		c.failure("scope missing/empty in client object");
	}
	req.form["scope"] = scope;
	c.success("Added scope of '" + scope + "' (" + source + ") to token endpoint request", { ...req.form });
}

function containsNoStore(header: string): boolean {
	return header.split(",").some((piece) => piece.trim() === "no-store");
}

/** upstream: condition/client/CheckTokenEndpointCacheHeaders.java (AbstractValidateResponseCacheHeaders) */
export function checkTokenEndpointCacheHeaders(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("CheckTokenEndpointCacheHeaders", ...requirements);
	const name = "token endpoint response";
	const cacheControl = res.headers["cache-control"];
	if (cacheControl === undefined) {
		c.failure(name + " does not contain 'cache-control' header", { response_headers: res.headers });
	}
	const hasNoStore = Array.isArray(cacheControl) ? cacheControl.some(containsNoStore) : containsNoStore(cacheControl);
	if (!hasNoStore) {
		c.failure("'cache-control' header in " + name + " does not contain expected value.", {
			expected: "no-store",
			actual: cacheControl,
		});
	}
	c.success("'cache-control' header in " + name + " contains expected value.", {
		cache_control_header: cacheControl,
	});
}

/** upstream: condition/client/CheckTokenTypeIsBearer.java */
export function checkTokenTypeIsBearer(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("CheckTokenTypeIsBearer", ...requirements);
	const tokenType = str(res.json, "token_type");
	if (!tokenType) {
		c.failure("Couldn't find token type");
	}
	if (tokenType.toLowerCase() !== "bearer") {
		c.failure("Token type is not bearer");
	}
	c.success("Token type is bearer");
}

/**
 * upstream: condition/AbstractEnsureMinimumEntropy.java. The actual amount of required entropy is 128 bits, but
 * entropy cannot be measured accurately so a bit of slop (96) is allowed for.
 */
function ensureMinimumEntropy(c: Condition, s: string): void {
	const requiredEntropy = 96;
	const entropy = shannonEntropy(s) * s.length;
	const fields = { value: s, expected: requiredEntropy, actual: entropy };
	if (entropy <= requiredEntropy) {
		c.failure(
			"Calculated shannon entropy does not seem to meet minimum required entropy (i.e. item is too short, or not random enough)",
			fields,
		);
	}
	c.success("Calculated shannon entropy seems sufficient", fields);
}

/** upstream: condition/client/EnsureMinimumAccessTokenEntropy.java */
export function ensureMinimumAccessTokenEntropy(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureMinimumAccessTokenEntropy", ...requirements);
	const accessToken = str(res.json, "access_token");
	if (!accessToken) {
		c.failure("Can't find access token");
	}
	ensureMinimumEntropy(c, accessToken);
}

/** upstream: condition/client/EnsureAccessTokenContainsAllowedCharactersOnly.java */
export function ensureAccessTokenContainsAllowedCharactersOnly(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureAccessTokenContainsAllowedCharactersOnly", ...requirements);
	const accessToken = str(res.json, "access_token");
	if (accessToken == null) {
		c.failure("Token endpoint response does not contain an access_token");
	}
	if (!/^(?:[\x20-\x7E]+)$/.test(accessToken)) {
		c.failure(
			"Access token contains illegal characters. As per RFC-6749, only characters between %x20 and %x7E are allowed.",
			{ access_token: accessToken },
		);
	}
	c.success("Access token does not contain any illegal characters");
}

/** upstream: condition/client/EnsureAccessTokenValuesAreDifferent.java */
export function ensureAccessTokenValuesAreDifferent(
	firstAccessToken: AccessToken,
	secondAccessToken: AccessToken,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureAccessTokenValuesAreDifferent", ...requirements);
	if (firstAccessToken.value === secondAccessToken.value) {
		c.failure("Access token values are not different");
	}
	c.success("Access token values are not the same", {
		first_access_token: firstAccessToken.value,
		second_access_token: secondAccessToken.value,
	});
}

/** upstream: condition/client/ExtractRefreshTokenFromTokenResponse.java */
export function extractRefreshTokenFromTokenResponse(res: TokenResponse, ...requirements: string[]): string {
	const c: Condition = condition("ExtractRefreshTokenFromTokenResponse", ...requirements);
	const refreshToken = str(res.json, "refresh_token");
	if (refreshToken == null) {
		// It's perfectly legal to NOT return a new refresh token; the caller then keeps using the old (still valid) one
		c.failure("Token endpoint response does not contain a refresh token");
	}
	c.success("Extracted refresh token from response", { refresh_token: refreshToken });
	return refreshToken;
}

/** upstream: condition/client/EnsureMinimumRefreshTokenLength.java */
export function ensureMinimumRefreshTokenLength(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureMinimumRefreshTokenLength", ...requirements);
	const requiredLength = 128;
	const refreshToken = str(res.json, "refresh_token");
	if (!refreshToken) {
		c.failure("Can't find refresh token");
	}
	const bitLength = Buffer.byteLength(refreshToken, "utf8") * 8;
	if (bitLength < requiredLength) {
		c.failure("Refresh token is not of sufficient length", { required: requiredLength, actual: bitLength });
	}
	c.success("Refresh token is of sufficient length", { required: requiredLength, actual: bitLength });
}

/** upstream: condition/client/EnsureMinimumRefreshTokenEntropy.java */
export function ensureMinimumRefreshTokenEntropy(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureMinimumRefreshTokenEntropy", ...requirements);
	const refreshToken = str(res.json, "refresh_token");
	if (!refreshToken) {
		c.failure("Can't find refresh token");
	}
	ensureMinimumEntropy(c, refreshToken);
}

/** upstream: condition/client/EnsureRefreshTokenContainsAllowedCharactersOnly.java */
export function ensureRefreshTokenContainsAllowedCharactersOnly(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureRefreshTokenContainsAllowedCharactersOnly", ...requirements);
	const refreshToken = str(res.json, "refresh_token");
	if (refreshToken == null) {
		c.success("Token endpoint response does not contain a refresh_token");
		return;
	}
	if (!/^(?:[\x20-\x7E]+)$/.test(refreshToken)) {
		c.failure(
			"Refresh token contains illegal characters. As per RFC-6749, only characters between %x20 and %x7E are allowed.",
			{ refresh_token: refreshToken },
		);
	}
	c.success("Refresh token does not contain any illegal characters");
}

/**
 * Uses the refresh token to fetch a new access token (and possibly an id_token and refresh token), and compares the
 * new id_token with the first one. The caller runs it in the block "Refresh Token Request".
 *
 * upstream: sequence/client/RefreshTokenRequestSteps.java (without DPoP)
 */
export async function refreshTokenRequestSteps(
	op: Pick<Op, "metadata" | "variant">,
	client: RegisteredClient,
	refreshToken: string,
	first: { accessToken: AccessToken; idToken: ParsedJwt },
	opts: { secondClient: boolean },
): Promise<RefreshedTokens> {
	const req = createRefreshTokenRequest(refreshToken);
	if (!opts.secondClient) {
		addScopeToTokenEndpointRequest(req, client.client, "RFC6749-6");
	}
	await addClientAuthentication(op, req, client);

	// wait 1 second to make sure that iat values will be different
	await waitForOneSecond();
	const res = await callTokenEndpoint(op, req);

	soft(() => checkTokenEndpointHttpStatus200(res, "RFC6749-5.1"));
	soft(() => checkTokenEndpointReturnedJsonContentType(res, "RFC6749-5.1"));
	soft(() => checkTokenEndpointCacheHeaders(res, "RFC6749-5.1"));
	checkIfTokenEndpointResponseError(res);

	const accessToken = extractAccessTokenFromTokenResponse(res);
	soft(() => checkTokenTypeIsBearer(res, "FAPI-R-6.2.2-1", "FAPI1-BASE-6.2.2-1"));
	soft(() => ensureMinimumAccessTokenEntropy(res, "FAPI-R-5.2.2-16", "FAPI1-BASE-5.2.2-16"));
	soft(() => ensureAccessTokenContainsAllowedCharactersOnly(res, "RFC6749-A.12"));
	const expiresIn = soft(() => extractExpiresInFromTokenEndpointResponse(res, "RFC6749-6", "RFC6749-5.1"), "warning");
	if (expiresIn === undefined) {
		skipped("ValidateExpiresIn", { object: "expires_in" }, "RFC6749-5.1");
	} else {
		soft(() => validateExpiresIn(expiresIn, "RFC6749-5.1"));
	}
	soft(() => ensureAccessTokenValuesAreDifferent(first.accessToken, accessToken), "info");

	if (client.keys == null) {
		skipped("ValidateIdTokenFromTokenResponseEncryption", { object: "client_jwks" });
	} else {
		soft(() => validateIdTokenFromTokenResponseEncryption(res, client.keys?.jwks), "info");
	}
	const idToken = await soft(() => extractIdTokenFromTokenResponse(res, client), "info");

	// It's perfectly legal to NOT return a new refresh token; if the server didn't, the old (still valid) token is
	// kept: it is used later to test the refresh token is bound to the client correctly.
	const newRefreshToken = soft(() => extractRefreshTokenFromTokenResponse(res), "info");

	if (str(res.json, "refresh_token") == null) {
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
		soft(() => ensureMinimumRefreshTokenLength(res, "RFC6749-10.10"));
		soft(() => ensureMinimumRefreshTokenEntropy(res, "RFC6749-10.10"));
	}

	// compare only when the refresh response contains an id_token
	if (idToken === undefined) {
		skipped("CompareIdTokenClaims", { object: "second_id_token" }, "OIDCC-12.2");
	} else {
		soft(() => compareIdTokenClaims(first.idToken, idToken, "OIDCC-12.2"));
	}
	return { accessToken, idToken, refreshToken: newRefreshToken ?? refreshToken };
}

/**
 * A refresh request with a refresh token issued to another client must fail with invalid_grant (RFC6749-5.2).
 *
 * upstream: sequence/client/RefreshTokenRequestExpectingErrorSteps.java (without DPoP)
 */
export async function refreshTokenRequestExpectingErrorSteps(
	op: Pick<Op, "metadata" | "variant">,
	client: RegisteredClient,
	refreshToken: string,
	opts: { secondClient: boolean },
): Promise<void> {
	const req = createRefreshTokenRequest(refreshToken);
	if (!opts.secondClient) {
		addScopeToTokenEndpointRequest(req, client.client, "RFC6749-6");
	}
	await addClientAuthentication(op, req, client);
	const res = await callTokenEndpoint(op, req);

	validateErrorFromTokenEndpointResponseError(res);
	soft(() => checkTokenEndpointHttpStatus400(res, "OIDCC-3.1.3.4"));
	soft(() => checkTokenEndpointReturnedJsonContentType(res, "OIDCC-3.1.3.4"));
	soft(() => checkErrorFromTokenEndpointResponseErrorInvalidGrant(res, "RFC6749-5.2"));
}

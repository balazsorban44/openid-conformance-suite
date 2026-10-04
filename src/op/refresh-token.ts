/**
 * The refresh token grant: a refresh request with the variant's client authentication, the checks on its response
 * (a new access token, maybe an id_token and refresh token) and the request a client must not be able to make with
 * another client's refresh token.
 *
 *   const refreshed = await block("Refresh Token Request", () =>
 *     refresh.refreshTokenRequestSteps(op, client, refreshToken, first));
 */
import { block, condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import type { ParsedJwt } from "../suite/jose.ts";
import { waitForOneSecond } from "../suite/wait.ts";
import { shannonEntropy } from "./authorization.ts";
import type { ServerMetadata } from "./discovery.ts";
import {
	addDpopHeaderForTokenEndpointRequest,
	callTokenEndpointAllowingDpopNonceError,
	checkTokenTypeIsDpop,
	createDpopClaims,
	createDpopHeader,
	createTokenEndpointDpopSteps,
	ensureDpopNonceContainsAllowedCharactersOnly,
	generateDpopKey,
	setDpopHtmHtuForTokenEndpoint,
	setDpopProofNonceForAuthorizationServer,
	signDpopProof,
	type DpopClient,
} from "./dpop.ts";
import { compareIdTokenClaims } from "./id-token.ts";
import type { Fapi2Variant, Op, OpVariant } from "./op.ts";
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
export function ensureMinimumEntropy(c: Condition, s: string): void {
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

/** The OP a refresh request goes to: an OIDCC or a FAPI 2 one (the latter always passes `addClientAuthentication`) */
export type RefreshTokenOp = Pick<Op<OpVariant | Fapi2Variant>, "metadata" | "variant">;

/** How a refresh request is made: upstream RefreshTokenRequestSteps' constructor arguments */
export interface RefreshTokenStepsOptions {
	secondClient: boolean;
	/**
	 * The client authentication to add (upstream `addClientAuthenticationToTokenEndpointRequest`; default: the
	 * variant's, `token.addClientAuthentication`)
	 */
	addClientAuthentication?: (req: TokenRequest) => Promise<void>;
	/**
	 * DPoP sender constraining (upstream `isDpop`): the proofs use this client's DPoP state; a new key is generated
	 * for the refresh request to check the server handles that correctly
	 */
	dpop?: DpopClient | null;
}

/** The DPoP proof for the refresh request and the call, retried once with the server's nonce (RFC9449-8.2) */
async function callTokenEndpointWithDpop(
	op: Pick<Op, "metadata">,
	req: TokenRequest,
	dpop: DpopClient,
	generateKey: boolean,
): Promise<TokenResponse> {
	if (generateKey) {
		// we generate a new key here, to check the server handles that correctly - so this isn't suitable for public
		// clients where the refresh token is bound to the dpop key
		await generateDpopKey(op.metadata, dpop);
	}
	await createTokenEndpointDpopSteps(op.metadata, dpop, req);
	let { response, nonceError } = await callTokenEndpointAllowingDpopNonceError(op, req, dpop.dpop);
	// retry request if token_endpoint_dpop_nonce_error is found
	await block("Token endpoint DPoP nonce retry", async () => {
		// repeat the conditions of CreateDpopProofSteps.createTokenEndpointDpopSteps() only if
		// token_endpoint_dpop_nonce_error is found (upstream: each wrapped in skipIfStringsMissing, so without the
		// error every one logs a skip and the original severities are lost)
		if (nonceError == null) {
			for (const name of [
				"CreateDpopHeader",
				"CreateDpopClaims",
				"SetDpopHtmHtuForTokenEndpoint",
				"SetDpopProofNonceForAuthorizationServer",
				"EnsureDpopNonceContainsAllowedCharactersOnly",
				"SignDpopProof",
				"AddDpopHeaderForTokenEndpointRequest",
				"CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse",
			]) {
				skipped(name, { string: "token_endpoint_dpop_nonce_error" });
			}
			return;
		}
		const header = createDpopHeader(dpop);
		const claims = createDpopClaims();
		setDpopHtmHtuForTokenEndpoint(claims, op.metadata);
		setDpopProofNonceForAuthorizationServer(claims, dpop.dpop);
		ensureDpopNonceContainsAllowedCharactersOnly(claims);
		const proof = await signDpopProof({ header, claims }, dpop);
		addDpopHeaderForTokenEndpointRequest(req, proof);
		({ response, nonceError } = await callTokenEndpointAllowingDpopNonceError(op, req, dpop.dpop));
	});
	return response;
}

/**
 * Uses the refresh token to fetch a new access token (and possibly an id_token and refresh token), and compares the
 * new id_token with the first one. The caller runs it in the block "Refresh Token Request" (upstream's `testTitle`).
 *
 * upstream: sequence/client/RefreshTokenRequestSteps.java
 */
export async function refreshTokenRequestSteps(
	op: RefreshTokenOp,
	client: Pick<RegisteredClient, "client" | "keys">,
	refreshToken: string,
	/** the first token response's tokens (idToken null with plain OAuth) */
	first: { accessToken: AccessToken; idToken: ParsedJwt | null },
	opts: RefreshTokenStepsOptions,
	/** upstream: the conditions a module inserts before ExtractIdTokenFromTokenResponse (ExpectNoIdTokenInTokenResponse) */
	beforeExtractIdToken?: (res: TokenResponse) => void,
): Promise<RefreshedTokens> {
	const req = createRefreshTokenRequest(refreshToken);
	if (!opts.secondClient) {
		addScopeToTokenEndpointRequest(req, client.client, "RFC6749-6");
	}
	if (opts.addClientAuthentication) {
		await opts.addClientAuthentication(req);
	} else {
		await addClientAuthentication(op as Pick<Op, "metadata" | "variant">, req, client as RegisteredClient);
	}

	// wait 1 second to make sure that iat values will be different
	await waitForOneSecond();
	const res = opts.dpop ? await callTokenEndpointWithDpop(op, req, opts.dpop, true) : await callTokenEndpoint(op, req);

	soft(() => checkTokenEndpointHttpStatus200(res, "RFC6749-5.1"));
	soft(() => checkTokenEndpointReturnedJsonContentType(res, "RFC6749-5.1"));
	soft(() => checkTokenEndpointCacheHeaders(res, "RFC6749-5.1"));
	checkIfTokenEndpointResponseError(res);

	const accessToken = extractAccessTokenFromTokenResponse(res);
	if (opts.dpop) {
		soft(() => checkTokenTypeIsDpop(res, "DPOP-5"));
	} else {
		soft(() => checkTokenTypeIsBearer(res, "FAPI-R-6.2.2-1", "FAPI1-BASE-6.2.2-1"));
	}
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
	beforeExtractIdToken?.(res);
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
	} else if (first.idToken == null) {
		skipped("CompareIdTokenClaims", { object: "first_id_token" }, "OIDCC-12.2");
	} else {
		soft(() => compareIdTokenClaims(first.idToken as ParsedJwt, idToken, "OIDCC-12.2"));
	}
	return { accessToken, idToken, refreshToken: newRefreshToken ?? refreshToken };
}

/**
 * A refresh request with a refresh token issued to another client must fail with invalid_grant (RFC6749-5.2).
 *
 * upstream: sequence/client/RefreshTokenRequestExpectingErrorSteps.java
 */
export async function refreshTokenRequestExpectingErrorSteps(
	op: RefreshTokenOp,
	client: Pick<RegisteredClient, "client" | "keys">,
	refreshToken: string,
	opts: RefreshTokenStepsOptions,
): Promise<void> {
	const req = createRefreshTokenRequest(refreshToken);
	if (!opts.secondClient) {
		addScopeToTokenEndpointRequest(req, client.client, "RFC6749-6");
	}
	if (opts.addClientAuthentication) {
		await opts.addClientAuthentication(req);
	} else {
		await addClientAuthentication(op as Pick<Op, "metadata" | "variant">, req, client as RegisteredClient);
	}
	const res = opts.dpop ? await callTokenEndpointWithDpop(op, req, opts.dpop, false) : await callTokenEndpoint(op, req);

	validateErrorFromTokenEndpointResponseError(res);
	soft(() => checkTokenEndpointHttpStatus400(res, "OIDCC-3.1.3.4"));
	soft(() => checkTokenEndpointReturnedJsonContentType(res, "OIDCC-3.1.3.4"));
	soft(() => checkErrorFromTokenEndpointResponseErrorInvalidGrant(res, "RFC6749-5.2"));
}

/** upstream: condition/client/FAPIEnsureServerConfigurationDoesNotSupportRefreshToken.java */
export function fapiEnsureServerConfigurationDoesNotSupportRefreshToken(
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	const c: Condition = condition("FAPIEnsureServerConfigurationDoesNotSupportRefreshToken", ...requirements);
	const supportedGrantTypes = metadata["grant_types_supported"];
	if (supportedGrantTypes == null) {
		// Null implies default ["authorization_code", "implicit"]
		c.success(
			"The server did not issue a refresh token and does not claim to support this grant type (grant_types_supported in not present in the discovery document)",
		);
		return;
	}
	if (!Array.isArray(supportedGrantTypes)) {
		c.failure("supported_grant_types is present in the discovery document but is not an array");
	}
	for (const grantType of supportedGrantTypes) {
		if (grantType === "refresh_token") {
			c.failure(
				"The server supports refresh tokens, but did not issue one. This is acceptable if the server has a policy of issuing refresh tokens to some clients, but not to FAPI clients. If the server requires scope=offline_access to issue a refresh token please add that to the scope listed in the test configuration.",
				{ supported_grant_types: supportedGrantTypes },
			);
		}
	}
	c.success("The server did not issue a refresh token, and does not claim to support this grant type", {
		supported_grant_types: supportedGrantTypes,
	});
}

/**
 * The token endpoint: the authorization code grant with the variant's client authentication, and the checks on
 * successful and error responses.
 *
 *   const tokenRequest = await token.createAuthorizationCodeRequest(op, client, code);
 *   const tokens = await token.requestAuthorizationCode(op, client, tokenRequest);
 *   ... tokens.accessToken, tokens.idToken (parsed), tokens.response ...
 */
import { condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import { endpointResponse, HttpError, request, type EndpointResponse } from "../suite/http.ts";
import { parseJwt, signJwt, type ParsedJwt } from "../suite/jose.ts";
import { JWE_FAMILY_ASYMMETRIC, keyTypeForAlgorithm } from "../suite/jose-algorithms.ts";
import { parseJWKSet } from "../suite/jose-jwk.ts";
import { ParseException, JOSEException } from "../suite/errors.ts";
import { parseJWT } from "../suite/jose-jwt.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import {
	checkContentType,
	checkErrorDescriptionContainsCRLFTAB,
	validateErrorDescription,
	validateErrorUri,
} from "./endpoint.ts";
import type { Op } from "./op.ts";
import type { RegisteredClient } from "./registration.ts";

/** A token endpoint request: form parameters and headers (upstream token_endpoint_request_form_parameters/_headers) */
export interface TokenRequest {
	form: Record<string, unknown>;
	headers: Record<string, string>;
}

/** The token endpoint's response (upstream token_endpoint_response_full; `json` is token_endpoint_response) */
export interface TokenResponse extends EndpointResponse {
	json: Record<string, unknown> | null;
}

export interface AccessToken {
	value: string;
	type: string;
}

/** upstream: condition/client/CreateTokenEndpointRequestForAuthorizationCodeGrant.java */
export function createTokenEndpointRequestForAuthorizationCodeGrant(code: string, redirectUri: string): TokenRequest {
	const form = { grant_type: "authorization_code", code, redirect_uri: redirectUri };
	condition("CreateTokenEndpointRequestForAuthorizationCodeGrant").success("Created token endpoint request", {
		...form,
	});
	return { form, headers: {} };
}

/**
 * client_secret_basic: the form-urlencoded client_id and secret in an Authorization: Basic header (RFC6749-2.3.1).
 *
 * upstream: condition/client/AddBasicAuthClientSecretToRequest.java
 */
export function addBasicAuthClientSecretToRequest(req: TokenRequest, client: RegisteredClient["client"]): void {
	const c: Condition = condition("AddBasicAuthClientSecretToRequest");
	if (client.client_id == null) {
		c.failure("Client ID not found in configuration");
	}
	if (client.client_secret == null) {
		c.failure("Client secret not found in configuration");
	}
	const pw = Buffer.from(formUrlEncode(client.client_id) + ":" + formUrlEncode(client.client_secret)).toString(
		"base64",
	);
	req.headers["Authorization"] = "Basic " + pw;
	c.success("Added basic authorization header", { ...req.headers });
}

/** Java URLEncoder.encode(s, UTF-8): application/x-www-form-urlencoded, space as '+', '*' '-' '.' '_' kept */
export function formUrlEncode(s: string): string {
	return encodeURIComponent(s)
		.replace(/[!'()~]/g, (ch) => "%" + ch.charCodeAt(0).toString(16).toUpperCase())
		.replace(/%20/g, "+");
}

/** upstream: condition/client/AddFormBasedClientSecretToRequest.java */
export function addFormBasedClientSecretToRequest(req: TokenRequest, client: RegisteredClient["client"]): void {
	req.form["client_id"] = client.client_id;
	req.form["client_secret"] = client.client_secret;
	condition("AddFormBasedClientSecretToRequest").log({ ...req.form });
}

/** upstream: condition/client/AddClientIdToRequest.java */
export function addClientIdToRequest(req: TokenRequest, client: RegisteredClient["client"]): void {
	const c: Condition = condition("AddClientIdToRequest");
	if (!client.client_id) {
		c.failure("client_id is null or empty");
	}
	req.form["client_id"] = client.client_id;
	c.log({ ...req.form });
}

/**
 * private_key_jwt / client_secret_jwt: a signed client assertion in the form.
 *
 * upstream: sequence/client/CreateJWTClientAuthenticationAssertionAndAddToTokenEndpointRequest.java with
 * condition/client/CreateClientAuthenticationAssertionClaims.java, SignClientAuthenticationAssertion.java,
 * AddClientAssertionToRequest.java (client_secret_jwt's HMAC key from GenerateJWKsFromClientSecret is not ported)
 */
export async function addClientAssertionToRequest(
	op: Pick<Op, "metadata">,
	req: TokenRequest,
	client: RegisteredClient,
	/** `updateClaims`: what a module changes in the claims before they are signed (upstream: a condition inserted after CreateClientAuthenticationAssertionClaims) */
	opts: { updateClaims?: (claims: Record<string, unknown>) => void } = {},
): Promise<void> {
	const create: Condition = condition("CreateClientAuthenticationAssertionClaims");
	const clientId = client.client.client_id;
	if (!clientId) {
		create.failure("Couldn't find required configuration element", { client_id: clientId });
	}
	const audience = op.metadata.token_endpoint;
	if (!audience) {
		create.failure("Couldn't find required configuration element", { audience });
	}
	const iat = Math.floor(Date.now() / 1000);
	const claims = {
		iss: clientId,
		sub: clientId,
		aud: audience,
		jti: randomAlphanumeric(20),
		nbf: iat,
		iat,
		exp: iat + 60,
	};
	create.success("Created client assertion claims", claims);
	opts.updateClaims?.(claims);

	const sign: Condition = condition("SignClientAuthenticationAssertion");
	if (client.keys == null) {
		sign.failure("Couldn't find jwks");
	}
	const { jws, verifiable } = await signJwt(sign, claims, client.keys.jwks);
	sign.success("Signed the client assertion", { client_assertion: verifiable });

	req.form["client_assertion"] = jws;
	req.form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
	condition("AddClientAssertionToRequest").log("Added client assertion", { ...req.form });
}

/** Adds the variant's client authentication to a token endpoint request (upstream addTokenEndpointClientAuthentication) */
export async function addClientAuthentication(
	op: Pick<Op, "metadata" | "variant">,
	req: TokenRequest,
	client: RegisteredClient,
): Promise<void> {
	switch (op.variant.client_auth_type) {
		case "client_secret_basic":
			return addBasicAuthClientSecretToRequest(req, client.client);
		case "client_secret_post":
			return addFormBasedClientSecretToRequest(req, client.client);
		case "none":
			return addClientIdToRequest(req, client.client);
		case "private_key_jwt":
			return addClientAssertionToRequest(op, req, client);
		default:
			throw new Error(`client_auth_type '${op.variant.client_auth_type}' is not supported by src/op yet`);
	}
}

/**
 * The token request for an authorization code, authenticated as the variant says.
 *
 * upstream: AbstractOIDCCServerTest.createAuthorizationCodeRequest
 */
export async function createAuthorizationCodeRequest(
	op: Pick<Op, "metadata" | "variant" | "redirectUri">,
	client: RegisteredClient,
	code: string,
): Promise<TokenRequest> {
	const req = createTokenEndpointRequestForAuthorizationCodeGrant(code, op.redirectUri);
	await addClientAuthentication(op, req, client);
	return req;
}

/**
 * POSTs the request to the token endpoint; any HTTP status is a response (the checks look at it).
 *
 * upstream: condition/client/CallTokenEndpointAndReturnFullResponse.java (AbstractCallOAuthEndpoint)
 */
export async function callTokenEndpoint(op: Pick<Op, "metadata">, req: TokenRequest): Promise<TokenResponse> {
	const c: Condition = condition("CallTokenEndpointAndReturnFullResponse");
	const endpoint = op.metadata.token_endpoint as string;
	const form = new URLSearchParams();
	for (const [k, v] of Object.entries(req.form)) {
		form.append(k, typeof v === "object" && v !== null ? JSON.stringify(v) : String(v));
	}
	let res;
	try {
		res = await request(c.name, {
			url: endpoint,
			method: "POST",
			headers: { ...req.headers, accept: "application/json" },
			body: form,
		});
	} catch (e) {
		if (e instanceof HttpError) {
			const cause = e.cause instanceof Error ? e.cause.message : null;
			c.failureFrom("Call to " + endpoint + " failed" + (cause ? " - " + cause : ""), e);
		}
		throw e;
	}
	// upstream records the endpoint URI as the endpoint name of the full response
	const response: TokenResponse = { ...endpointResponse(endpoint, res), json: null };
	if (!res.body) {
		c.failure("Missing or empty response from the token endpoint");
	}
	if (response.body_json === undefined) {
		try {
			JSON.parse(res.body);
		} catch (e) {
			c.failureFrom("Error parsing " + endpoint + " response body as JSON", e);
		}
		c.failure("token endpoint did not return a JSON object", { response: res.body });
	}
	response.json = response.body_json as Record<string, unknown>;
	const { json: _json, ...full } = response;
	c.success("Parsed token endpoint response", full);
	return response;
}

/** upstream: condition/client/AbstractCheckTokenEndpointHttpStatus.java */
function checkTokenEndpointHttpStatus(
	name: string,
	res: TokenResponse,
	expected: number,
	...requirements: string[]
): void {
	const c: Condition = condition(name, ...requirements);
	if (res.status == null) {
		c.failure("Http status can not be null.");
	}
	if (res.status !== expected) {
		c.failure("Invalid http status", { actual: res.status, expected });
	}
	c.success("Token endpoint http status code was " + expected);
}

/** upstream: condition/client/CheckTokenEndpointHttpStatus200.java */
export function checkTokenEndpointHttpStatus200(res: TokenResponse, ...requirements: string[]): void {
	checkTokenEndpointHttpStatus("CheckTokenEndpointHttpStatus200", res, 200, ...requirements);
}

/** upstream: condition/client/CheckTokenEndpointHttpStatus400.java */
export function checkTokenEndpointHttpStatus400(res: TokenResponse, ...requirements: string[]): void {
	checkTokenEndpointHttpStatus("CheckTokenEndpointHttpStatus400", res, 400, ...requirements);
}

function str(o: Record<string, unknown> | null, key: string): string | null {
	const v = o?.[key];
	return typeof v === "string" ? v : null;
}

/** upstream: condition/client/CheckIfTokenEndpointResponseError.java */
export function checkIfTokenEndpointResponseError(res: TokenResponse): void {
	const c: Condition = condition("CheckIfTokenEndpointResponseError");
	if (res.json == null) {
		c.failure("Couldn't find token endpoint response");
	}
	if (str(res.json, "error")) {
		c.failure("The token endpoint call was expected to succeed, but it returned an error response", res.json);
	}
	c.success("No error from token endpoint");
}

/** upstream: condition/client/CheckForAccessTokenValue.java */
export function checkForAccessTokenValue(res: TokenResponse): void {
	const c: Condition = condition("CheckForAccessTokenValue");
	if (!str(res.json, "access_token")) {
		c.failure("access_token is missing or empty in token endpoint response");
	}
	if (!str(res.json, "token_type")) {
		c.failure("token_type is missing or empty in token endpoint response");
	}
	c.success("Found an access token", { access_token: str(res.json, "access_token") });
}

/** upstream: condition/client/ExtractAccessTokenFromTokenResponse.java (AbstractExtractAccessToken) */
export function extractAccessTokenFromTokenResponse(res: TokenResponse): AccessToken {
	const c: Condition = condition("ExtractAccessTokenFromTokenResponse");
	const value = str(res.json, "access_token");
	if (!value) {
		c.failure("Couldn't find access token in token_endpoint_response");
	}
	const type = str(res.json, "token_type");
	if (!type) {
		c.failure("Couldn't find token type in token_endpoint_response");
	}
	const token = { value, type };
	c.success("Extracted the access token", token);
	return token;
}

/** upstream: condition/client/ExtractExpiresInFromTokenEndpointResponse.java */
export function extractExpiresInFromTokenEndpointResponse(res: TokenResponse, ...requirements: string[]): unknown {
	const c: Condition = condition("ExtractExpiresInFromTokenEndpointResponse", ...requirements);
	const expiresIn = res.json?.["expires_in"];
	if (expiresIn === undefined) {
		c.failure(
			"'expires_in' not present in the token endpoint response. RFC6749 recommends expires_in is included.",
			res.json ?? {},
		);
	}
	c.success("Extracted 'expires_in'", { expires_in: expiresIn });
	return expiresIn;
}

/** upstream: condition/client/ValidateExpiresIn.java */
export function validateExpiresIn(expiresIn: unknown, ...requirements: string[]): void {
	const c: Condition = condition("ValidateExpiresIn", ...requirements);
	if (typeof expiresIn === "object") {
		c.failure("expires_in is not a JSON primitive");
	}
	if (typeof expiresIn !== "number") {
		c.failure("expires_in is not a number");
	}
	if (Math.trunc(expiresIn) <= 0) {
		// RFC6749 appendix A.14 technically allows 0, but a token that has already expired is nonsensical
		c.failure("expires_in must be positive");
	}
	if (Math.trunc(expiresIn) > 31536000) {
		c.failure(
			"expires_in is unreasonably large (more than 1 year), this may indicate the value was incorrectly specified in milliseconds instead of seconds",
			{ expires_in: expiresIn },
		);
	}
	c.success("expires_in passed all validation checks", { expires_in: expiresIn });
}

/** upstream: condition/client/CheckForRefreshTokenValue.java */
export function checkForRefreshTokenValue(res: TokenResponse): string {
	const c: Condition = condition("CheckForRefreshTokenValue");
	const refreshToken = str(res.json, "refresh_token");
	if (!refreshToken) {
		c.failure("Couldn't find refresh token");
	}
	c.success("Found a refresh token", { refresh_token: refreshToken });
	return refreshToken;
}

/**
 * An encrypted id_token must be encrypted to a key the client has (upstream AbstractVerifyJweEncryption).
 *
 * upstream: condition/client/ValidateIdTokenFromTokenResponseEncryption.java
 */
export function validateIdTokenFromTokenResponseEncryption(
	res: TokenResponse,
	clientJwks: unknown,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateIdTokenFromTokenResponseEncryption", ...requirements);
	const idToken = res.json?.["id_token"];
	if (idToken == null || typeof idToken === "object") {
		c.failure("Couldn't find id_token in token_endpoint_response");
	}
	if (verifyJweEncryption(c, String(idToken), clientJwks, "id_token")) {
		c.success("The client has a valid asymmetric key to decrypt the id_token");
	} else {
		c.success("The id_token is not encrypted using an asymmetric encryption algorithm");
	}
}

/** upstream: condition/client/AbstractVerifyJweEncryption.java; true when encrypted to one of the client's keys */
export function verifyJweEncryption(c: Condition, token: string, jwks: unknown, tokenName: string): boolean {
	try {
		const jwt = parseJWT(token);
		if (jwt.type !== "encrypted") {
			return false;
		}
		const kid = typeof jwt.header["kid"] === "string" ? jwt.header["kid"] : null;
		const alg = typeof jwt.header["alg"] === "string" ? jwt.header["alg"] : null;
		if (alg == null) {
			c.failure("The JWE header does not contain alg. This is required.", { [tokenName]: token });
		}
		const kty = keyTypeForAlgorithm(alg);
		if (kty == null) {
			// UPSTREAM: KeyType.forAlgorithm returns null and Java throws a NullPointerException
			throw new TypeError("KeyType.forAlgorithm returned null for " + alg);
		}
		if (!JWE_FAMILY_ASYMMETRIC.includes(alg)) {
			return false;
		}
		const keys = parseJWKSet(JSON.stringify(jwks)).keys;
		const ofType = keys.filter((k) => k["kty"] === kty).length;
		const withKid = keys.filter((k) => k["kty"] === kty && kid != null && k["kid"] === kid).length;
		const details = { jwks, kid, kty, [tokenName]: token };
		if (kid != null && ofType > 1 && withKid === 0) {
			c.failure("Found multiple keys in JWKS of the correct type, but none with matching kid hint.", details);
		}
		if (kid != null && withKid > 1) {
			c.failure("Found multiple keys in JWKS of the correct type and with the same kid hint.", details);
		}
		if (kid == null && ofType > 1) {
			c.failure("Found multiple keys in JWKS of the correct type but no kid hint in JWE header.", {
				jwks,
				kty,
				[tokenName]: token,
			});
		}
		if (kid != null && ofType === 1 && withKid === 0) {
			c.failure("Single key in JWKS of the correct type, but does not match kid hint.", details);
		}
		return true;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Error validating " + tokenName + " encryption", e);
		}
		throw e;
	}
}

/**
 * Parses (decrypting with the client's keys if needed) the id_token of a token endpoint response.
 *
 * upstream: condition/client/ExtractIdTokenFromTokenResponse.java (AbstractExtractJWT)
 */
export async function extractIdTokenFromTokenResponse(
	res: TokenResponse,
	client: RegisteredClient,
	...requirements: string[]
): Promise<ParsedJwt> {
	const c: Condition = condition("ExtractIdTokenFromTokenResponse", ...requirements);
	const key = "token_endpoint_response";
	const token = res.json?.["id_token"];
	if (token == null || typeof token === "object") {
		c.failure("Couldn't find id_token in " + key);
	}
	try {
		const parsed = await parseJwt(String(token), client.client, client.keys?.jwks ?? null);
		if (parsed == null) {
			c.failure("Couldn't parse id_token from " + key + " as a JWT", { id_token: token });
		}
		c.success("Found and parsed the id_token from " + key, { ...parsed });
		return parsed;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse id_token from " + key + " as a JWT", e, { id_token: token });
		}
		if (
			e instanceof JOSEException ||
			(e as Error).name?.startsWith("JOSE") ||
			(e as { code?: string }).code?.startsWith("ERR_J")
		) {
			c.failureFrom("Decrypting id_token from " + key + " failed", e, { id_token: token });
		}
		throw e;
	}
}

export interface Tokens {
	response: TokenResponse;
	accessToken: AccessToken;
	/** `expires_in` when present */
	expiresIn: unknown;
	refreshToken: string | undefined;
	idToken: ParsedJwt;
}

/**
 * Exchanges the code and checks the successful token response: status 200, no error, an access token (and its
 * type), expires_in when present, the id_token (encryption, parsing). Upstream's order and severities.
 *
 * upstream: AbstractOIDCCServerTest.requestAuthorizationCode (callTokenEndpoint + the checks up to
 * ExtractIdTokenFromTokenResponse)
 */
export async function requestAuthorizationCode(
	op: Pick<Op, "metadata">,
	client: RegisteredClient,
	req: TokenRequest,
	/**
	 * For modules that look at the response first (upstream overrides requestAuthorizationCode): the response of a
	 * callTokenEndpoint() already made, and whether it must have status 200 (CheckTokenEndpointHttpStatus200)
	 */
	opts: { response?: TokenResponse; checkStatus?: boolean } = {},
): Promise<Tokens> {
	const response = opts.response ?? (await callTokenEndpoint(op, req));
	if (opts.checkStatus !== false) {
		checkTokenEndpointHttpStatus200(response);
	}
	checkIfTokenEndpointResponseError(response);
	checkForAccessTokenValue(response);
	const accessToken = extractAccessTokenFromTokenResponse(response);
	// 'recommended' by the RFC, but a warning on every test would be noise
	const expiresIn = soft(() => extractExpiresInFromTokenEndpointResponse(response, "RFC6749-5.1"), "info");
	if (expiresIn === undefined) {
		skipped("ValidateExpiresIn", { object: "expires_in" }, "RFC6749-5.1");
	} else {
		soft(() => validateExpiresIn(expiresIn, "RFC6749-5.1"));
	}
	const refreshToken = soft(() => checkForRefreshTokenValue(response), "info");
	if (client.keys == null) {
		skipped("ValidateIdTokenFromTokenResponseEncryption", { object: "client_jwks" }, "OIDCC-10.2");
	} else {
		soft(() => validateIdTokenFromTokenResponseEncryption(response, client.keys?.jwks, "OIDCC-10.2"), "warning");
	}
	const idToken = await extractIdTokenFromTokenResponse(response, client, "OIDCC-3.1.3.3", "OIDCC-3.3.3.3");
	return { response, accessToken, expiresIn, refreshToken, idToken };
}

/** upstream: condition/client/CheckTokenEndpointReturnedJsonContentType.java */
export function checkTokenEndpointReturnedJsonContentType(res: TokenResponse, ...requirements: string[]): void {
	checkContentType(
		"CheckTokenEndpointReturnedJsonContentType",
		"token_endpoint_response_headers",
		res.headers["content-type"],
		"application/json",
		...requirements,
	);
}

/** upstream: condition/client/AbstractCheckErrorFromResponseError.java (token endpoint) */
function checkErrorFromTokenEndpointResponseError(
	name: string,
	res: TokenResponse,
	expected: string[],
	...requirements: string[]
): void {
	const c: Condition = condition(name, ...requirements);
	const key = "token_endpoint_response";
	if (res.json == null) {
		c.failure("Couldn't find " + key);
	}
	const error = str(res.json, "error");
	if (!error) {
		c.failure("Couldn't find error field");
	}
	if (!expected.includes(error)) {
		c.failure("'error' field has unexpected value", { expected, actual: error });
	}
	c.success(key + " error returned expected 'error' of '" + error + "'", { expected });
}

/** upstream: condition/client/CheckErrorFromTokenEndpointResponseErrorInvalidGrant.java */
export function checkErrorFromTokenEndpointResponseErrorInvalidGrant(
	res: TokenResponse,
	...requirements: string[]
): void {
	checkErrorFromTokenEndpointResponseError(
		"CheckErrorFromTokenEndpointResponseErrorInvalidGrant",
		res,
		["invalid_grant"],
		...requirements,
	);
}

/** upstream: condition/client/ValidateErrorFromTokenEndpointResponseError.java */
export function validateErrorFromTokenEndpointResponseError(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("ValidateErrorFromTokenEndpointResponseError", ...requirements);
	const error = str(res.json, "error");
	if (!error) {
		c.failure(
			"The authorization server was expected to return an error, but the 'error' field in the response is either null or empty",
		);
	}
	if (!/^(?:[\x20-\x21\x23-\x5B\x5D-\x7E]+)$/.test(error)) {
		c.failure("'error' field MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E", { error });
	}
	c.success("Token endpoint response error returned valid 'error' field", { error });
}

/**
 * A token endpoint error response: status 400, JSON, the expected error code, well-formed error fields.
 *
 * upstream: AbstractOIDCCAuthCodeReuse.checkResponse (with the expected error invalid_grant)
 */
export function checkInvalidGrantErrorResponse(res: TokenResponse): void {
	const name = "token_endpoint_response";
	const json = res.json ?? {};
	soft(() => checkTokenEndpointHttpStatus400(res, "OIDCC-3.1.3.4"));
	soft(() => checkTokenEndpointReturnedJsonContentType(res, "OIDCC-3.1.3.4"));
	soft(() => checkErrorFromTokenEndpointResponseErrorInvalidGrant(res, "RFC6749-5.2"));
	soft(() => validateErrorFromTokenEndpointResponseError(res, "RFC6749-5.2"));
	soft(
		() =>
			checkErrorDescriptionContainsCRLFTAB(
				"CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB",
				name,
				json,
				"RFC6749-5.2",
			),
		"warning",
	);
	soft(() =>
		validateErrorDescription("ValidateErrorDescriptionFromTokenEndpointResponseError", name, json, "RFC6749-5.2"),
	);
	soft(() => validateErrorUri("ValidateErrorUriFromTokenEndpointResponseError", name, json, "RFC6749-5.2"));
}

/**
 * The answer to a second token request with the same code: an invalid_grant error, or (a warning) a success.
 *
 * upstream: OIDCCAuthCodeReuse.checkResponse / AbstractOIDCCAuthCodeReuse.checkResponse
 */
export function checkAuthorizationCodeReuseResponse(res: TokenResponse): void {
	if (res.status === 200) {
		soft(() => serverAllowedReusingAuthorizationCode(), "warning");
	} else {
		checkInvalidGrantErrorResponse(res);
	}
}

/** upstream: condition/client/ServerAllowedReusingAuthorizationCode.java */
export function serverAllowedReusingAuthorizationCode(): never {
	return condition("ServerAllowedReusingAuthorizationCode").failure(
		"Server has incorrectly allowed a second use of an authorization code; an authorization code is expected to be single use.",
	);
}

/** upstream: condition/client/AddCodeVerifierToTokenEndpointRequest.java */
export function addCodeVerifierToTokenEndpointRequest(
	req: TokenRequest,
	codeVerifier: string,
	...requirements: string[]
): void {
	const c: Condition = condition("AddCodeVerifierToTokenEndpointRequest", ...requirements);
	if (!codeVerifier) {
		c.failure("Couldn't find code_verifier value");
	}
	req.form["code_verifier"] = codeVerifier;
	c.log({ ...req.form });
}

/**
 * The audience of the client assertion is the OP's issuer instead of the token endpoint.
 *
 * upstream: condition/client/UpdateClientAuthenticationAssertionClaimsWithISSAud.java
 */
export function updateClientAuthenticationAssertionClaimsWithISSAud(
	claims: Record<string, unknown>,
	metadata: Pick<Op["metadata"], "issuer">,
): void {
	const c: Condition = condition("UpdateClientAuthenticationAssertionClaimsWithISSAud");
	delete claims["aud"];
	const audience = metadata.issuer;
	if (!audience) {
		c.failure("Couldn't find required configuration element", { issuer: audience });
	}
	claims["aud"] = audience;
	c.success("Updated audience in client assertion claims", claims);
}

/** upstream: condition/client/CheckTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError.java */
export function checkTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError(
	res: TokenResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError", ...requirements);
	const httpStatus = res.status;
	if (httpStatus == null) {
		c.failure("Http status can not be null.");
	}
	const error = str(res.json, "error");
	if (!error) {
		c.failure("Couldn't find error field");
	}
	if (error === "invalid_client") {
		if (httpStatus !== 400 && httpStatus !== 401) {
			c.failure("Invalid http status for error invalid_client", { actual: httpStatus, expected: "400 or 401" });
		}
	} else if (httpStatus !== 400) {
		c.failure("Http status must be 400 for token endpoint errors other than invalid_client", {
			actual: httpStatus,
			expected: 400,
		});
	}
	c.success("Token endpoint http status code was " + httpStatus + " for error '" + error + "'");
}

/** upstream: condition/client/CheckErrorFromTokenEndpointResponseErrorInvalidClient.java */
export function checkErrorFromTokenEndpointResponseErrorInvalidClient(
	res: TokenResponse,
	...requirements: string[]
): void {
	checkErrorFromTokenEndpointResponseError(
		"CheckErrorFromTokenEndpointResponseErrorInvalidClient",
		res,
		["invalid_client"],
		...requirements,
	);
}

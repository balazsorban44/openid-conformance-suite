/**
 * The token endpoint: the authorization code grant with the variant's client authentication, and the checks on
 * successful and error responses.
 *
 *   const tokenRequest = await token.createAuthorizationCodeRequest(op, client, code);
 *   const tokens = await token.requestAuthorizationCode(op, client, tokenRequest);
 *   ... tokens.accessToken, tokens.idToken (parsed), tokens.response ...
 */
import { condition, errorFields, skipped, soft, type Condition } from "../suite/conditions.ts";
import { endpointResponse, HttpError, request, type EndpointResponse } from "../suite/http.ts";
import { parseJwt, signJwt, type ParsedJwt } from "../suite/jose.ts";
import { JWE_FAMILY_ASYMMETRIC, keyTypeForAlgorithm } from "../suite/jose-algorithms.ts";
import { parseJWKSet } from "../suite/jose-jwk.ts";
import { ParseException, JOSEException } from "../suite/errors.ts";
import { parseClaimsSet, parseJWT, parseSignedJWT } from "../suite/jose-jwt.ts";
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
export function addClientIdToRequest(
	req: Pick<TokenRequest, "form">,
	client: RegisteredClient["client"],
	...requirements: string[]
): void {
	const c: Condition = condition("AddClientIdToRequest", ...requirements);
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
 * What a variant of CallTokenEndpointAndReturnFullResponse (a subclass upstream) adds: the condition it logs under,
 * what it does with the full response before the "Parsed ... response" entry (upstream addFullResponse; a failure
 * there ends the call) and the suffix of that entry's message (upstream parsedResponseLogSuffix).
 */
export interface CallTokenEndpointOptions {
	conditionName?: string;
	/** the requirements the call site cites (upstream callAndStopOnFailure(CallTokenEndpoint..., requirements)) */
	requirements?: string[];
	onResponse?: (c: Condition, res: TokenResponse) => void;
	parsedResponseLogSuffix?: (res: TokenResponse) => string;
	/** upstream handleClientException override: a network / TLS failure is a result (the call returns null) */
	onHttpError?: (c: Condition, e: HttpError) => void;
	/** upstream handleJsonParseException override: a body that is not JSON is a result (`json` stays null) */
	onJsonParseError?: (c: Condition) => void;
}

/**
 * POSTs the request to the token endpoint; any HTTP status is a response (the checks look at it).
 *
 * upstream: condition/client/CallTokenEndpointAndReturnFullResponse.java (AbstractCallOAuthEndpoint)
 */
export async function callTokenEndpoint(
	op: Pick<Op, "metadata">,
	req: TokenRequest,
	opts: CallTokenEndpointOptions = {},
): Promise<TokenResponse> {
	// null only with onHttpError, whose callers use callTokenEndpointOrNull
	return (await callTokenEndpointOrNull(op, req, opts)) as TokenResponse;
}

/** callTokenEndpoint for the variants that accept a failed connection as a result (null then) */
export async function callTokenEndpointOrNull(
	op: Pick<Op, "metadata">,
	req: TokenRequest,
	opts: CallTokenEndpointOptions = {},
): Promise<TokenResponse | null> {
	const c: Condition = condition(
		opts.conditionName ?? "CallTokenEndpointAndReturnFullResponse",
		...(opts.requirements ?? []),
	);
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
			if (opts.onHttpError) {
				opts.onHttpError(c, e);
				return null;
			}
			const cause = e.cause instanceof Error ? e.cause.message : null;
			c.failureFrom("Call to " + endpoint + " failed" + (cause ? " - " + cause : ""), e);
		}
		throw e;
	}
	// upstream records the endpoint URI as the endpoint name of the full response
	const response: TokenResponse = { ...endpointResponse(endpoint, res), json: null };
	response.json = (response.body_json as Record<string, unknown> | undefined) ?? null;
	opts.onResponse?.(c, response);
	if (!res.body) {
		c.failure("Missing or empty response from the token endpoint");
	}
	if (response.body_json === undefined) {
		try {
			JSON.parse(res.body);
		} catch (e) {
			if (opts.onJsonParseError) {
				opts.onJsonParseError(c);
				return response;
			}
			c.failureFrom("Error parsing " + endpoint + " response body as JSON", e);
		}
		c.failure("token endpoint did not return a JSON object", { response: res.body });
	}
	const { json: _json, ...full } = response;
	c.success("Parsed token endpoint response" + (opts.parsedResponseLogSuffix?.(response) ?? ""), full);
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
	client: Pick<RegisteredClient, "client" | "keys">,
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
	soft(() => checkTokenEndpointHttpStatus400(res, "OIDCC-3.1.3.4"));
	soft(() => checkTokenEndpointReturnedJsonContentType(res, "OIDCC-3.1.3.4"));
	soft(() => checkErrorFromTokenEndpointResponseErrorInvalidGrant(res, "RFC6749-5.2"));
	soft(() => validateErrorFromTokenEndpointResponseError(res, "RFC6749-5.2"));
	validateTokenEndpointErrorFields(res);
}

/**
 * The optional error_description / error_uri checks of a token endpoint error response (the three conditions every
 * module runs after ValidateErrorFromTokenEndpointResponseError, with upstream's severities and requirements)
 */
export function validateTokenEndpointErrorFields(res: TokenResponse): void {
	soft(() => checkErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB(res, "RFC6749-5.2"), "warning");
	soft(() => validateErrorDescriptionFromTokenEndpointResponseError(res, "RFC6749-5.2"));
	soft(() => validateErrorUriFromTokenEndpointResponseError(res, "RFC6749-5.2"));
}

/** upstream: condition/client/CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB.java */
export function checkErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB(
	res: TokenResponse,
	...requirements: string[]
): void {
	checkErrorDescriptionContainsCRLFTAB(
		"CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB",
		"token_endpoint_response",
		res.json ?? {},
		...requirements,
	);
}

/** upstream: condition/client/ValidateErrorDescriptionFromTokenEndpointResponseError.java */
export function validateErrorDescriptionFromTokenEndpointResponseError(
	res: TokenResponse,
	...requirements: string[]
): void {
	validateErrorDescription(
		"ValidateErrorDescriptionFromTokenEndpointResponseError",
		"token_endpoint_response",
		res.json ?? {},
		...requirements,
	);
}

/** upstream: condition/client/ValidateErrorUriFromTokenEndpointResponseError.java */
export function validateErrorUriFromTokenEndpointResponseError(res: TokenResponse, ...requirements: string[]): void {
	validateErrorUri(
		"ValidateErrorUriFromTokenEndpointResponseError",
		"token_endpoint_response",
		res.json ?? {},
		...requirements,
	);
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
export function serverAllowedReusingAuthorizationCode(...requirements: string[]): never {
	return condition("ServerAllowedReusingAuthorizationCode", ...requirements).failure(
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

/** upstream: condition/client/CheckErrorFromTokenEndpointResponseErrorInvalidClientOrInvalidGrant.java */
export function checkErrorFromTokenEndpointResponseErrorInvalidClientOrInvalidGrant(
	res: TokenResponse,
	...requirements: string[]
): void {
	checkErrorFromTokenEndpointResponseError(
		"CheckErrorFromTokenEndpointResponseErrorInvalidClientOrInvalidGrant",
		res,
		["invalid_client", "invalid_grant"],
		...requirements,
	);
}

/** upstream: condition/client/CheckErrorFromTokenEndpointResponseErrorInvalidClientOrInvalidRequest.java */
export function checkErrorFromTokenEndpointResponseErrorInvalidClientOrInvalidRequest(
	res: TokenResponse,
	...requirements: string[]
): void {
	checkErrorFromTokenEndpointResponseError(
		"CheckErrorFromTokenEndpointResponseErrorInvalidClientOrInvalidRequest",
		res,
		["invalid_request", "invalid_client"],
		...requirements,
	);
}

/** upstream: condition/client/CheckTokenEndpointHttpStatus400or401.java */
export function checkTokenEndpointHttpStatus400or401(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("CheckTokenEndpointHttpStatus400or401", ...requirements);
	if (res.status == null) {
		c.failure("Http status can not be null.");
	}
	if (res.status !== 400 && res.status !== 401) {
		c.failure("Invalid http status", { actual: res.status, expected: "400 or 401" });
	}
	c.success("Token endpoint http status code was " + res.status);
}

/** upstream: condition/client/AbstractCheckTokenEndpointReturnedExpectedErrorAndHttpStatus.java */
function checkTokenEndpointReturnedExpectedErrorAndHttpStatus(
	name: string,
	res: TokenResponse,
	errorStatusMap: Record<string, number[]>,
	requirements: string[],
): void {
	const c: Condition = condition(name, ...requirements);
	const httpStatus = res.status;
	if (httpStatus == null) {
		c.failure("Http status can not be null.");
	}
	const error = str(res.json, "error");
	if (!error) {
		c.failure("Couldn't find error field");
	}
	if (!Object.hasOwn(errorStatusMap, error)) {
		c.failure("Unexpected error '" + error + "' received", { actual: error, expected: Object.keys(errorStatusMap) });
	}
	const expectedHttpStatusCodes = errorStatusMap[error];
	if (!expectedHttpStatusCodes.includes(httpStatus)) {
		c.failure("Invalid http status with error " + error, { actual: httpStatus, expected: expectedHttpStatusCodes });
	}
	c.success("Token endpoint returned error " + error + " and the http status code was " + httpStatus);
}

/** upstream: condition/client/CheckTokenEndpointReturnedInvalidRequestGrantOrDPopProofError.java */
export function checkTokenEndpointReturnedInvalidRequestGrantOrDPopProofError(
	res: TokenResponse,
	...requirements: string[]
): void {
	checkTokenEndpointReturnedExpectedErrorAndHttpStatus(
		"CheckTokenEndpointReturnedInvalidRequestGrantOrDPopProofError",
		res,
		{ invalid_request: [400], invalid_grant: [400], invalid_dpop_proof: [400] },
		requirements,
	);
}

/** upstream: condition/client/CheckTokenEndpointReturnedInvalidClientGrantOrRequestError.java */
export function checkTokenEndpointReturnedInvalidClientGrantOrRequestError(
	res: TokenResponse,
	...requirements: string[]
): void {
	checkTokenEndpointReturnedExpectedErrorAndHttpStatus(
		"CheckTokenEndpointReturnedInvalidClientGrantOrRequestError",
		res,
		{ invalid_request: [400], invalid_grant: [400], invalid_client: [400, 401] },
		requirements,
	);
}

/** upstream: condition/client/ExpectNoIdTokenInTokenResponse.java */
export function expectNoIdTokenInTokenResponse(res: TokenResponse): void {
	const c: Condition = condition("ExpectNoIdTokenInTokenResponse");
	if (res.json != null && Object.hasOwn(res.json, "id_token")) {
		c.failure("Test is not targeting Open ID Connect but the token endpoint response contains an ID token.");
	}
	c.success("Test is not targeting Open ID Connect and the token endpoint response does not contain an ID token");
}

/** upstream: condition/client/EnsureMinimumAccessTokenLength.java */
export function ensureMinimumAccessTokenLength(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureMinimumAccessTokenLength", ...requirements);
	const requiredLength = 128;
	const accessToken = str(res.json, "access_token");
	if (!accessToken) {
		c.failure("Can't find access token");
	}
	const bitLength = Buffer.byteLength(accessToken, "utf8") * 8;
	if (bitLength >= requiredLength) {
		c.success("Access token is of sufficient length", { required: requiredLength, actual: bitLength });
		return;
	}
	c.failure("Access token is not of sufficient length", { required: requiredLength, actual: bitLength });
}

/**
 * Inverts the case of every letter of the token type ("DPoP" -> "dpOp") for the next resource request, to test that
 * the resource server treats the authentication scheme case-insensitively (RFC9110-11.1).
 *
 * upstream: condition/client/SetAccessTokenTypeToInvertedCase.java
 */
export function setAccessTokenTypeToInvertedCase(accessToken: AccessToken, ...requirements: string[]): void {
	const c: Condition = condition("SetAccessTokenTypeToInvertedCase", ...requirements);
	if (!accessToken.type) {
		c.failure("token_type not available");
	}
	accessToken.type = Array.from(accessToken.type, (ch) =>
		/\p{L}/u.test(ch) ? (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()) : ch,
	).join("");
	c.success("Set token endpoint request token type to inverted case letters", { type: accessToken.type });
}

/**
 * Calls the token endpoint accepting a dropped TLS connection as a response (an OP may refuse a request without the
 * client certificate at the TLS layer): `sslError` says whether that happened, `response` is null then.
 *
 * upstream: condition/client/CallTokenEndpointAllowingTLSFailure.java
 */
export async function callTokenEndpointAllowingTLSFailure(
	op: Pick<Op, "metadata">,
	req: TokenRequest,
	...requirements: string[]
): Promise<{ response: TokenResponse | null; sslError: boolean }> {
	let sslError = false;
	const response = await callTokenEndpointOrNull(op, req, {
		conditionName: "CallTokenEndpointAllowingTLSFailure",
		requirements,
		// the ssl connection was dropped (Java: a ResourceAccessException caused by an SSLException / SocketException)
		onHttpError: (c, e) => {
			sslError = true;
			c.success("Call to token_endpoint failed due to a TLS issue", errorFields(e));
		},
		onJsonParseError: (c) => c.log("token endpoint response parsed but not valid JSON"),
	});
	return { response, sslError };
}

/**
 * The claims of a client assertion whose audience is the OP's issuer (FAPI 2.0 5.3.2.1-8), valid for 60 seconds.
 *
 * upstream: condition/client/CreateClientAuthenticationAssertionClaimsWithIssAudience.java
 */
export function createClientAuthenticationAssertionClaimsWithIssAudience(
	op: Pick<Op, "metadata">,
	client: Pick<RegisteredClient["client"], "client_id">,
): Record<string, unknown> {
	const c: Condition = condition("CreateClientAuthenticationAssertionClaimsWithIssAudience");
	const clientId = client.client_id;
	if (!clientId) {
		c.failure("Couldn't find required configuration element", { client_id: clientId });
	}
	const audience = op.metadata.issuer;
	if (!audience) {
		c.failure("Couldn't find required configuration element", { issuer: audience });
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
	c.success("Created client assertion claims", claims);
	return claims;
}

/** upstream: condition/client/SignClientAuthenticationAssertion.java (AbstractSignJWT) */
export async function signClientAuthenticationAssertion(
	claims: Record<string, unknown>,
	client: Pick<RegisteredClient, "keys">,
): Promise<string> {
	const c: Condition = condition("SignClientAuthenticationAssertion");
	if (client.keys == null) {
		c.failure("Couldn't find jwks");
	}
	const { jws, verifiable } = await signJwt(c, claims, client.keys.jwks);
	c.success("Signed the client assertion", { client_assertion: verifiable });
	return jws;
}

/** upstream: condition/client/AddClientAssertionToRequest.java (the client assertion into the request form) */
export function addSignedClientAssertionToRequest(req: Pick<TokenRequest, "form">, clientAssertion: string): void {
	req.form["client_assertion"] = clientAssertion;
	req.form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
	condition("AddClientAssertionToRequest").log("Added client assertion", { ...req.form });
}

/** upstream: condition/client/RemoveClientAssertionFromRequest.java */
export function removeClientAssertionFromRequest(req: Pick<TokenRequest, "form">): void {
	delete req.form["client_assertion"];
	delete req.form["client_assertion_type"];
	condition("RemoveClientAssertionFromRequest").log("Removed any client assertion from the request", { ...req.form });
}

/**
 * What a module changes in the client assertion sequence (upstream: conditions inserted into / replacing the ones of
 * CreateJWTClientAuthenticationAssertionWithIssAudAndAddToTokenEndpointRequest, e.g. the invalid assertions of
 * fapi2-security-profile-final-ensure-invalid-client-assertions-fail)
 */
export interface ClientAssertionMutation {
	/** replaces CreateClientAuthenticationAssertionClaimsWithIssAudience (e.g. CreateClientAuthenticationAssertionClaims) */
	createClaims?: () => Record<string, unknown>;
	/** inserted after CreateClientAuthenticationAssertionClaimsWithIssAudience */
	afterClaims?: (claims: Record<string, unknown>) => void;
	/** inserted before SignClientAuthenticationAssertion */
	beforeSign?: () => void;
	/** replaces SignClientAuthenticationAssertion */
	sign?: (claims: Record<string, unknown>) => Promise<string>;
	/** inserted after SignClientAuthenticationAssertion: returns the (altered) assertion */
	afterSign?: (clientAssertion: string) => string;
	/** inserted after AddClientAssertionToRequest */
	afterAdd?: (req: Pick<TokenRequest, "form">) => void;
}

/**
 * private_key_jwt client authentication with the issuer as audience: the assertion claims, signed with the client's
 * key, added to the request form (a token or PAR request).
 *
 * upstream: sequence/client/CreateJWTClientAuthenticationAssertionWithIssAudAndAddToTokenEndpointRequest.java with
 * condition/client/CreateClientAuthenticationAssertionClaimsWithIssAudience.java, SignClientAuthenticationAssertion.java,
 * AddClientAssertionToRequest.java
 */
export async function createJWTClientAuthenticationAssertionWithIssAudAndAddToRequest(
	op: Pick<Op, "metadata">,
	req: Pick<TokenRequest, "form">,
	client: Pick<RegisteredClient, "client" | "keys">,
	mutation: ClientAssertionMutation = {},
): Promise<void> {
	const claims = mutation.createClaims
		? mutation.createClaims()
		: createClientAuthenticationAssertionClaimsWithIssAudience(op, client.client);
	mutation.afterClaims?.(claims);
	mutation.beforeSign?.();
	let clientAssertion = mutation.sign
		? await mutation.sign(claims)
		: await signClientAuthenticationAssertion(claims, client);
	if (mutation.afterSign) {
		clientAssertion = mutation.afterSign(clientAssertion);
	}
	addSignedClientAssertionToRequest(req, clientAssertion);
	mutation.afterAdd?.(req);
}

/** upstream: condition/client/RemoveClientAssertionTypeFromRequest.java */
export function removeClientAssertionTypeFromRequest(req: Pick<TokenRequest, "form">, ...requirements: string[]): void {
	delete req.form["client_assertion_type"];
	condition("RemoveClientAssertionTypeFromRequest", ...requirements).log(
		"Removed 'client_assertion_type' from the request, making it invalid",
		{ ...req.form },
	);
}

/** upstream: condition/client/SetClientAssertionTypeToWrongValue.java */
export function setClientAssertionTypeToWrongValue(req: Pick<TokenRequest, "form">, ...requirements: string[]): void {
	req.form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:invalid";
	condition("SetClientAssertionTypeToWrongValue", ...requirements).log(
		"Set 'client_assertion_type' to a value that is not a registered assertion type, making the request invalid",
		{ ...req.form },
	);
}

/** upstream: condition/client/RemoveSubFromClientAssertionClaims.java */
export function removeSubFromClientAssertionClaims(claims: Record<string, unknown>, ...requirements: string[]): void {
	delete claims["sub"];
	condition("RemoveSubFromClientAssertionClaims", ...requirements).log(
		"Removed 'sub' from client_assertion_claims, making it invalid",
		{ ...claims },
	);
}

/** upstream: condition/client/SetSubToWrongValueInClientAssertionClaims.java */
export function setSubToWrongValueInClientAssertionClaims(
	claims: Record<string, unknown>,
	...requirements: string[]
): void {
	claims["sub"] = "wrong-sub-value";
	condition("SetSubToWrongValueInClientAssertionClaims", ...requirements).success(
		"Set wrong sub in client_assertion_claims",
		{ ...claims },
	);
}

/** upstream: condition/client/RemoveIssFromClientAssertionClaims.java */
export function removeIssFromClientAssertionClaims(claims: Record<string, unknown>, ...requirements: string[]): void {
	delete claims["iss"];
	condition("RemoveIssFromClientAssertionClaims", ...requirements).log(
		"Removed 'iss' from client_assertion_claims, making it invalid",
		{ ...claims },
	);
}

/** upstream: condition/client/AddWrongIssToClientAssertionClaims.java */
export function addWrongIssToClientAssertionClaims(claims: Record<string, unknown>, ...requirements: string[]): void {
	claims["iss"] = "wrong-issuer-value";
	condition("AddWrongIssToClientAssertionClaims", ...requirements).success(
		"Added wrong iss to client_assertion_claims",
		{
			...claims,
		},
	);
}

/** upstream: condition/client/RemoveAudFromClientAssertionClaims.java */
export function removeAudFromClientAssertionClaims(claims: Record<string, unknown>, ...requirements: string[]): void {
	delete claims["aud"];
	condition("RemoveAudFromClientAssertionClaims", ...requirements).log(
		"Removed 'aud' from client_assertion_claims, making it invalid",
		{ ...claims },
	);
}

/** upstream: condition/client/AddWrongAudToClientAssertionClaims.java */
export function addWrongAudToClientAssertionClaims(claims: Record<string, unknown>, ...requirements: string[]): void {
	claims["aud"] = "https://fapidev-rs.authlete.net/api/userinfo";
	condition("AddWrongAudToClientAssertionClaims", ...requirements).success(
		"Added wrong aud to client_assertion_claims",
		{
			...claims,
		},
	);
}

/** upstream: condition/client/AddPAREndpointAsAudToClientAuthenticationAssertionClaims.java */
export function addPAREndpointAsAudToClientAuthenticationAssertionClaims(
	claims: Record<string, unknown>,
	op: Pick<Op, "metadata">,
	...requirements: string[]
): void {
	const c: Condition = condition("AddPAREndpointAsAudToClientAuthenticationAssertionClaims", ...requirements);
	const audience = op.metadata["pushed_authorization_request_endpoint"];
	if (typeof audience !== "string" || !audience) {
		c.failure("Couldn't find required configuration element", { audience: audience ?? null });
	}
	claims["aud"] = audience;
	c.success("add audience in client assertion claims", { ...claims });
}

/** upstream: condition/client/AddTokenEndpointAsAudToClientAuthenticationAssertionClaims.java */
export function addTokenEndpointAsAudToClientAuthenticationAssertionClaims(
	claims: Record<string, unknown>,
	op: Pick<Op, "metadata">,
	...requirements: string[]
): void {
	const c: Condition = condition("AddTokenEndpointAsAudToClientAuthenticationAssertionClaims", ...requirements);
	const audience = op.metadata.token_endpoint;
	if (!audience) {
		c.failure("Couldn't find required configuration element", { audience: audience ?? null });
	}
	claims["aud"] = audience;
	c.success("add audience in client assertion claims", { ...claims });
}

/** upstream: condition/client/AddArrayContainingIssuerAndAnotherValueAsAudToClientAuthenticationAssertionClaims.java */
export function addArrayContainingIssuerAndAnotherValueAsAudToClientAuthenticationAssertionClaims(
	claims: Record<string, unknown>,
	op: Pick<Op, "metadata">,
	...requirements: string[]
): void {
	const c: Condition = condition(
		"AddArrayContainingIssuerAndAnotherValueAsAudToClientAuthenticationAssertionClaims",
		...requirements,
	);
	const aud: unknown[] = [op.metadata.issuer ?? null];
	const audience = op.metadata.token_endpoint;
	if (!audience) {
		c.failure("Couldn't find required configuration element", { audience: audience ?? null });
	}
	aud.push(audience);
	claims["aud"] = aud;
	c.success("Set audience in client assertion claims to be an array containing the issuer and another value", {
		...claims,
	});
}

/** upstream: condition/client/AddExpIs5MinutesInPastToClientAssertionClaims.java */
export function addExpIs5MinutesInPastToClientAssertionClaims(
	claims: Record<string, unknown>,
	...requirements: string[]
): void {
	claims["exp"] = Math.floor(Date.now() / 1000) - 5 * 60;
	condition("AddExpIs5MinutesInPastToClientAssertionClaims", ...requirements).success(
		"Added 'exp' is 5 minutes in the past to client_assertion_claims",
		{ ...claims },
	);
}

/** java.time.Instant.toString() of a second count */
function instantString(seconds: number): string {
	return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

/** upstream: condition/client/AddIatNbfExpOver60SecondsInTheFutureToClientAuthenticationAssertionClaims.java */
export function addIatNbfExpOver60SecondsInTheFutureToClientAuthenticationAssertionClaims(
	claims: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition(
		"AddIatNbfExpOver60SecondsInTheFutureToClientAuthenticationAssertionClaims",
		...requirements,
	);
	const offsetSeconds = 62;
	const adjust = (name: string): string | null => {
		if (!Object.hasOwn(claims, name)) {
			return null;
		}
		const time = Math.trunc(Number(claims[name])) + offsetSeconds;
		claims[name] = time;
		return instantString(time);
	};
	const iatTime = adjust("iat");
	const nbfTime = adjust("nbf");
	const expTime = adjust("exp");
	c.success("Added iat/nbf/exp values to client assertion claims which are 62 seconds in the future", {
		client_assertion_claims: claims,
		nbf_is_62_seconds_in_the_future: nbfTime,
		iat_is_62_seconds_in_the_future: iatTime,
		exp_is_62_seconds_in_the_future: expTime,
	});
}

/** upstream: condition/client/AddIatNbf8SecondsInTheFutureToClientAuthenticationAssertionClaims.java */
export function addIatNbf8SecondsInTheFutureToClientAuthenticationAssertionClaims(
	claims: Record<string, unknown>,
	...requirements: string[]
): void {
	const time = Math.floor(Date.now() / 1000) + 8;
	claims["iat"] = time;
	claims["nbf"] = time;
	condition("AddIatNbf8SecondsInTheFutureToClientAuthenticationAssertionClaims", ...requirements).success(
		"Added iat/nbf values to client assertion claims which are 8 seconds in the future",
		{
			client_assertion_claims: claims,
			nbf_is_8_seconds_in_the_future: instantString(time),
			iat_is_8_seconds_in_the_future: instantString(time),
		},
	);
}

/**
 * Sets `alg` of every key of the client's JWKS to RS256 (in place: the caller restores the keys afterwards).
 *
 * upstream: condition/client/ChangeClientJwksAlgToRS256.java
 */
export function changeClientJwksAlgToRS256(client: Pick<RegisteredClient, "keys">, ...requirements: string[]): void {
	const c: Condition = condition("ChangeClientJwksAlgToRS256", ...requirements);
	const jwks = client.keys?.jwks;
	if (jwks == null) {
		c.failure("Couldn't find jwks");
	}
	for (const key of jwks.keys as Record<string, unknown>[]) {
		key["alg"] = "RS256";
	}
	c.success("Added RS256 as algorithm", { client_jwks: jwks });
}

/**
 * The client assertion claims as an unsecured JWT ("alg": "none", empty signature).
 *
 * upstream: condition/client/CreateUnsecuredClientAuthenticationAssertion.java
 */
export function createUnsecuredClientAuthenticationAssertion(
	claims: Record<string, unknown>,
	...requirements: string[]
): string {
	const c: Condition = condition("CreateUnsecuredClientAuthenticationAssertion", ...requirements);
	try {
		// new PlainJWT(JWTClaimsSet.parse(claims)).serialize()
		const claimSet = parseClaimsSet(claims as never);
		const jwt =
			Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url") +
			"." +
			Buffer.from(JSON.stringify(claimSet)).toString("base64url") +
			".";
		c.log("Created an unsecured client assertion using the 'none' algorithm", { client_assertion: jwt });
		return jwt;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse client assertion claims", e, { client_assertion_claims: claims });
		}
		throw e;
	}
}

/**
 * Flips bits of the assertion's signature so it no longer verifies.
 *
 * upstream: condition/client/InvalidateClientAssertionSignature.java (AbstractInvalidateJwsSignature)
 */
export function invalidateClientAssertionSignature(clientAssertion: string, ...requirements: string[]): string {
	const c: Condition = condition("InvalidateClientAssertionSignature", ...requirements);
	let parsed;
	try {
		parsed = parseSignedJWT(clientAssertion);
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse JWT", e, { client_assertion: clientAssertion });
		}
		throw e;
	}
	const bytes = Buffer.from(parsed.signature ?? "", "base64url");
	// Flip some of the bits in the signature to make it invalid
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] ^= 0x5a;
	}
	const invalid = parsed.parts[0] + "." + parsed.parts[1] + "." + bytes.toString("base64url");
	c.log("Made the client_assertion signature invalid", { client_assertion: invalid });
	return invalid;
}

/** upstream: condition/client/ServerAllowedExpiredAuthorizationCode.java */
export function serverAllowedExpiredAuthorizationCode(...requirements: string[]): never {
	return condition("ServerAllowedExpiredAuthorizationCode", ...requirements).failure(
		"Server has incorrectly allowed the use of an expired authorization code.",
	);
}

/**
 * The claims of a client assertion whose audience is the token endpoint (OIDCC 9), valid for 60 seconds.
 *
 * upstream: condition/client/CreateClientAuthenticationAssertionClaims.java
 */
export function createClientAuthenticationAssertionClaims(
	op: Pick<Op, "metadata">,
	client: Pick<RegisteredClient["client"], "client_id">,
): Record<string, unknown> {
	const c: Condition = condition("CreateClientAuthenticationAssertionClaims");
	const clientId = client.client_id;
	if (!clientId) {
		c.failure("Couldn't find required configuration element", { client_id: clientId });
	}
	// This code uses the mtls aliased token endpoint if there is one
	// This is probably not correct, according to this ticket we should always use the non-MTLS one:
	// https://bitbucket.org/openid/mobile/issues/203/mtls-aliases-ambiguity-in-private_key_jwt
	// (mTLS is not ported: the metadata's token_endpoint)
	const audience = op.metadata.token_endpoint;
	if (!audience) {
		c.failure("Couldn't find required configuration element", { audience });
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
	c.success("Created client assertion claims", claims);
	return claims;
}

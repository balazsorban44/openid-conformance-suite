/**
 * Request objects at the emulated OP's authorization endpoint (request_type request_object / request_uri): the
 * metadata that announces them, fetching the request_uri (or reading the `request` parameter), the checks upstream
 * runs on the request object (exp, iat, iss, aud, signature with the client's keys, parameters matching the plain
 * request parameters) and the module checks of the request_uri tests.
 */
import { isDeepStrictEqual } from "node:util";
import { condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import { HttpError, request } from "../suite/http.ts";
import { parseJwksLenientlyLoggingSkips, parseJwt, type Jwks, type ParsedJwt } from "../suite/jose.ts";
import { currentLog } from "../suite/log.ts";
import { getString } from "../suite/json.ts";
import { isSymmetricJWEAlgorithm } from "../suite/jose-jwe.ts";
import { getPublicJwksAsJsonObject, toPublicJWK, importKey, type JWK } from "../suite/jose-jwk.ts";
import { EC_CURVE_ALGORITHM } from "../suite/jose-algorithms.ts";
import { isJOSEException, JOSEException, ParseException } from "../suite/errors.ts";
import { selectJWSJwks, verifySignedJWT, type JWSVerifier } from "../suite/jose-jws.ts";
import { parseSignedJWT } from "../suite/jose-jwt.ts";
import type { AuthorizationParams } from "./authorization.ts";
import { FAPI2_ALLOWED_ALGS, type ServerMetadata } from "./discovery.ts";
import type { EmulatedOp, RpVariant } from "./op.ts";
import type { RpClient } from "./registration.ts";

/** A string member (OIDFJSON.getString): null when absent or JSON null, an error for another type */
function str(o: Record<string, unknown>, name: string): string | null {
	const v = o[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

/** A numeric claim (Environment.getLong): null when absent or JSON null */
function long(o: Record<string, unknown>, name: string): number | null {
	const v = o[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "number") {
		throw new Error(`A number is required for authorization_request_object claims.${name} but ${typeof v} was found`);
	}
	return Math.trunc(v);
}

// ---------------------------------------------------------------------------------------------------------------
// the server configuration

/** upstream: condition/as/SetRequestParameterSupportedToTrueInServerConfiguration.java */
export function setRequestParameterSupportedToTrueInServerConfiguration(
	server: ServerMetadata,
	...requirements: string[]
): void {
	server["request_parameter_supported"] = true;
	condition("SetRequestParameterSupportedToTrueInServerConfiguration", ...requirements).log(
		"Enabled request parameter support in server configuration",
		{ server },
	);
}

/** upstream: condition/as/SetRequestUriParameterSupportedToTrueInServerConfiguration.java */
export function setRequestUriParameterSupportedToTrueInServerConfiguration(
	server: ServerMetadata,
	...requirements: string[]
): void {
	server["request_uri_parameter_supported"] = true;
	server["require_request_uri_registration"] = false;
	condition("SetRequestUriParameterSupportedToTrueInServerConfiguration", ...requirements).log(
		"Enabled request_uri support in server configuration",
		{ server },
	);
}

/** upstream: condition/as/OIDCCAddRequestObjectSigningAlgValuesSupportedToServerConfiguration.java */
export function oidccAddRequestObjectSigningAlgValuesSupportedToServerConfiguration(
	server: ServerMetadata,
	...requirements: string[]
): void {
	server["request_object_signing_alg_values_supported"] = ["none", "RS256", "PS256", "ES256", "EdDSA"];
	condition("OIDCCAddRequestObjectSigningAlgValuesSupportedToServerConfiguration", ...requirements).log(
		"Added request_object_signing_alg_values_supported to server configuration",
		{ server },
	);
}

/**
 * Announces request objects in the metadata for request_type request_object / request_uri.
 *
 * upstream: AbstractOIDCCClientTest.onServerConfigurationCompleted
 */
export function configureRequestObjectSupport(server: ServerMetadata, requestType: RpVariant["request_type"]): void {
	if (requestType === "request_object") {
		setRequestParameterSupportedToTrueInServerConfiguration(server, "OIDCC-6.1");
		oidccAddRequestObjectSigningAlgValuesSupportedToServerConfiguration(server, "OIDCC-6.1");
	} else if (requestType === "request_uri") {
		setRequestUriParameterSupportedToTrueInServerConfiguration(server, "OIDCC-6.2");
	}
}

// ---------------------------------------------------------------------------------------------------------------
// the client metadata (module checks)

/** upstream: condition/as/dynregistration/EnsureRequestObjectSigningAlgIsNoneInClientMetadata.java */
export function ensureRequestObjectSigningAlgIsNoneInClientMetadata(
	client: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureRequestObjectSigningAlgIsNoneInClientMetadata", ...requirements);
	const alg = str(client, "request_object_signing_alg");
	if (alg === "none") {
		c.success("request_object_signing_alg is none");
		return;
	}
	c.failure("Unexpected request_object_signing_alg. 'none' is required for this test.", {
		actual: alg,
		expected: "none",
	});
}

/** upstream: condition/as/dynregistration/EnsureRequestObjectSigningAlgIsRS256InClientMetadata.java */
export function ensureRequestObjectSigningAlgIsRS256InClientMetadata(
	client: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureRequestObjectSigningAlgIsRS256InClientMetadata", ...requirements);
	const alg = str(client, "request_object_signing_alg");
	if (alg === "RS256") {
		c.success("request_object_signing_alg is RS256");
		return;
	}
	c.failure("Unexpected request_object_signing_alg. RS256 is required for this test.", {
		actual: alg,
		expected: "RS256",
	});
}

// ---------------------------------------------------------------------------------------------------------------
// getting the request object

/**
 * Parses a request object (decrypting it with the OP's encryption keys when it is a JWE).
 *
 * upstream: condition/as/AbstractExtractRequestObject.java (processRequestObjectString)
 */
export async function processRequestObjectString(
	c: Condition,
	requestObjectString: string | null,
	client: RpClient | null,
	serverEncryptionKeys: Jwks | null,
): Promise<ParsedJwt> {
	if (!requestObjectString) {
		c.failure("Could not find request object in request parameters");
	}
	try {
		const requestObject = await parseJwt(requestObjectString, client, serverEncryptionKeys as never);
		c.success("Parsed request object", { request_object: requestObject });
		return requestObject;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse request object: " + e.message, e, { request: requestObjectString });
		}
		if (isJOSEException(e)) {
			c.failureFrom("Request object decryption failed", e, { request: requestObjectString });
		}
		throw e;
	}
}

/** upstream: condition/as/ExtractRequestObject.java */
export async function extractRequestObject(
	params: AuthorizationParams,
	client: RpClient | null,
	serverEncryptionKeys: Jwks | null,
	...requirements: string[]
): Promise<ParsedJwt> {
	const c: Condition = condition("ExtractRequestObject", ...requirements);
	return processRequestObjectString(c, str(params, "request"), client, serverEncryptionKeys);
}

/** upstream: condition/as/FetchRequestUriAndExtractRequestObject.java */
export async function fetchRequestUriAndExtractRequestObject(
	params: AuthorizationParams,
	client: RpClient | null,
	serverEncryptionKeys: Jwks | null,
	...requirements: string[]
): Promise<ParsedJwt> {
	const c: Condition = condition("FetchRequestUriAndExtractRequestObject", ...requirements);
	const requestUri = str(params, "request_uri");
	if (!requestUri) {
		c.failure("Authorization endpoint request does not contain a request_uri parameter", {
			authorization_endpoint_http_request_params: params,
		});
	}
	c.log("Fetching request object from request_uri", { request_uri: requestUri });
	let requestObjectString: string | null = "";
	try {
		const res = await request(c.name, { url: requestUri, method: "GET" });
		// RestTemplate.getForObject throws a RestClientException (with no cause) for 4xx/5xx responses
		if (res.status >= 400) {
			throw new HttpError(res.status + " " + res.statusText + ": " + (res.body ? '"' + res.body + '"' : "[no body]"));
		}
		requestObjectString = res.body;
		c.log("Downloaded request object", { request_object: requestObjectString });
		// request object will be decrypted if it's encrypted
		// UPSTREAM: an empty response body makes Java throw a NullPointerException here
		const requestObject = await parseJwt(requestObjectString ?? "", client, serverEncryptionKeys as never);
		c.success("Parsed request object", { ...requestObject });
		return requestObject;
	} catch (e) {
		if (e instanceof HttpError) {
			// Java: an I/O error (ResourceAccessException) has the underlying exception as its cause
			const cause = e.cause instanceof Error ? e.cause : null;
			c.failureFrom("Unable to fetch request_uri from " + requestUri + (cause != null ? " - " + cause.message : ""), e);
		}
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse request object", e, { request: requestObjectString });
		}
		if (isJOSEException(e)) {
			c.failureFrom("Couldn't decrypt request object", e, {
				request: requestObjectString,
				keys: serverEncryptionKeys,
			});
		}
		throw e;
	}
}

/**
 * OIDCC 6.2: the request_uri must be https unless the request object is signed in a way the OP can verify. The
 * request object is fetched first even when the request_uri is not https.
 *
 * upstream: condition/as/EnsureRequestUriIsHttpsOrRequestObjectIsSigned.java
 */
export function ensureRequestUriIsHttpsOrRequestObjectIsSigned(
	params: AuthorizationParams,
	requestObject: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureRequestUriIsHttpsOrRequestObjectIsSigned", ...requirements);
	const requestUri = str(params, "request_uri") as string;
	const alg = str(requestObject.header, "alg");
	if (requestUri.toLowerCase().startsWith("https://")) {
		c.success("request_uri is a https url", { request_uri: requestUri });
		return;
	}
	// OIDCC-6.1: The Request Object MAY be signed or unsigned (plaintext). When it is plaintext, this is indicated
	// by use of the none algorithm [JWA] in the JOSE Header.
	if (alg !== "none") {
		c.success("request_uri is not a https url but the request object is signed", { request_uri: requestUri, alg });
		return;
	}
	c.failure("The scheme used in the request_uri value MUST be https, as the target Request Object is not signed", {
		request_uri: requestUri,
		alg,
	});
}

/**
 * The request object of the RP's authorization request: fetched from request_uri (request_type request_uri) or
 * read from the `request` parameter (request_type request_object). A failure ends the test.
 *
 * upstream: AbstractOIDCCClientTest.extractAuthorizationEndpointRequestParameters (fetchAndProcessRequestUri /
 * ExtractRequestObject)
 */
export async function extractRequestObjectFromAuthorizationRequest(
	op: EmulatedOp,
	params: AuthorizationParams,
	requestType: RpVariant["request_type"] = op.variant.request_type,
): Promise<ParsedJwt> {
	if (requestType === "request_uri") {
		const requestObject = await fetchRequestUriAndExtractRequestObject(
			params,
			op.client,
			op.keys.encryptionKeys,
			"OIDCC-6.2",
		);
		// the OP under test (suite-vs-suite) fetches the suite's own request_uris, which are http in CI
		if (!op.options.opUnderTest) {
			ensureRequestUriIsHttpsOrRequestObjectIsSigned(params, requestObject, "OIDCC-6.2");
		}
		return requestObject;
	}
	return extractRequestObject(params, op.client, op.keys.encryptionKeys, "OIDCC-6.1");
}

// ---------------------------------------------------------------------------------------------------------------
// the request object's claims

const TIME_SKEW_MILLIS = 5 * 60 * 1000; // 5 minute allowable skew for testing

/** exp is optional: the caller skips the check without it. upstream: condition/as/OIDCCValidateRequestObjectExp.java */
export function oidccValidateRequestObjectExp(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("OIDCCValidateRequestObjectExp", ...requirements);
	const now = Date.now();
	const exp = long(requestObject.claims, "exp");
	if (exp == null) {
		c.failure("Missing exp, request object does not contain an 'exp' claim");
	}
	if (now - TIME_SKEW_MILLIS > exp * 1000) {
		c.failure("Request object expired", { exp: new Date(exp * 1000), now: new Date(now) });
	}
	if (exp * 1000 > now + 50 * 365 * 24 * 60 * 60 * 1000) {
		c.failure(
			"'exp' is unreasonably far in the future (more than 50 years), this may indicate the value was incorrectly specified in milliseconds instead of seconds",
			{ exp: new Date(exp * 1000), now: new Date(now) },
		);
	}
	c.success("Request object contains a valid exp claim, expiry time", { exp: new Date(exp * 1000) });
}

/** upstream: condition/as/ValidateRequestObjectIat.java */
export function validateRequestObjectIat(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("ValidateRequestObjectIat", ...requirements);
	const now = Date.now();
	const iat = long(requestObject.claims, "iat");
	if (iat == null) {
		c.log({ msg: "Request object does not contain an 'iat' claim", result: "INFO" });
	} else {
		if (now + TIME_SKEW_MILLIS < iat * 1000) {
			c.failure("Token issued in the future, 'iat' claim value is in the future", {
				"issued-at": new Date(iat * 1000),
				now: new Date(now),
			});
		}
		if (now - 24 * 60 * 60 * 1000 > iat * 1000) {
			c.failure("'iat' is more than 1 day in the past", { "issued-at": new Date(iat * 1000), now: new Date(now) });
		}
	}
	c.success("iat claim is valid", { iat });
}

/** Names of numeric claims (EnsureNumericRequestObjectClaimsAreNotNull.numericClaimNames) */
const NUMERIC_CLAIM_NAMES = ["max_age"];

/** Only logs WARNINGs. upstream: condition/as/EnsureNumericRequestObjectClaimsAreNotNull.java */
export function ensureNumericRequestObjectClaimsAreNotNull(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("EnsureNumericRequestObjectClaimsAreNotNull", ...requirements);
	const nulls: Record<string, string> = {};
	for (const name of NUMERIC_CLAIM_NAMES) {
		if (Object.hasOwn(requestObject.claims, name) && requestObject.claims[name] === null) {
			nulls[name] = "Should have a numeric value.";
		}
	}
	if (Object.keys(nulls).length > 0) {
		c.failure(
			"Request object contains null value(s) for claim(s) that are expected to have numeric values." +
				" This is allowed but not recommended.",
			{ claims: nulls },
		);
	}
	c.success("None of the claims expected to have numeric values, have null values", {
		numeric_claims: NUMERIC_CLAIM_NAMES,
	});
}

/** upstream: condition/as/ValidateRequestObjectMaxAge.java */
export function validateRequestObjectMaxAge(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("ValidateRequestObjectMaxAge", ...requirements);
	if (!Object.hasOwn(requestObject.claims, "max_age")) {
		c.log("Request object does not contain a max_age claim");
		return;
	}
	const maxAge = requestObject.claims["max_age"];
	if (maxAge === null) {
		// EnsureNumericRequestObjectClaimsAreNotNull handles the JsonNull case
		c.log("max_age has a 'json null' value");
		return;
	}
	if (typeof maxAge !== "number") {
		c.failure("max_age is not encoded as a number", { max_age: maxAge });
	}
	c.success("max_age is correctly encoded as a number", { max_age: maxAge });
}

/** OIDCC 6.1. upstream: condition/as/EnsureRequestObjectDoesNotContainRequestOrRequestUri.java */
export function ensureRequestObjectDoesNotContainRequestOrRequestUri(
	requestObject: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureRequestObjectDoesNotContainRequestOrRequestUri", ...requirements);
	const requestClaim = str(requestObject.claims, "request");
	const requestUriClaim = str(requestObject.claims, "request_uri");
	if (requestClaim != null && requestUriClaim != null) {
		c.failure("request and request_uri parameters MUST NOT be included in Request Objects", {
			request: requestClaim,
			request_uri: requestUriClaim,
		});
	} else if (requestClaim != null) {
		c.failure("request parameter MUST NOT be included in Request Objects", { request: requestClaim });
	} else if (requestUriClaim != null) {
		c.failure("request_uri parameter MUST NOT be included in Request Objects", { request_uri: requestUriClaim });
	}
	c.success("Request object does not contain request or request_uri");
}

/** JAR 10.8. upstream: condition/as/EnsureRequestObjectDoesNotContainSubWithClientId.java */
export function ensureRequestObjectDoesNotContainSubWithClientId(
	requestObject: ParsedJwt,
	client: RpClient,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureRequestObjectDoesNotContainSubWithClientId", ...requirements);
	const sub = str(requestObject.claims, "sub");
	if (sub && sub === client.client_id) {
		c.failure(
			"Request object sub must not be Client ID - this is a security concern as it may allow the request object to be used as a client authentication assertion.",
			{ sub: client.client_id },
		);
	}
	c.success("Request object does not contain Client Id in sub");
}

/** upstream: condition/as/ValidateRequestObjectIss.java */
export function validateRequestObjectIss(requestObject: ParsedJwt, client: RpClient, ...requirements: string[]): void {
	const c: Condition = condition("ValidateRequestObjectIss", ...requirements);
	const iss = str(requestObject.claims, "iss");
	if (iss == null) {
		c.failure("Missing issuer, request object does not contain an 'iss' claim");
	}
	if (client.client_id !== iss) {
		c.failure("Issuer mismatch, iss claim does not match the client id", { expected: client.client_id, actual: iss });
	}
	c.success("iss claim matches the client id", { iss });
}

/** `issuer`: the OP's (upstream "server".issuer). upstream: condition/as/ValidateRequestObjectAud.java */
export function validateRequestObjectAud(requestObject: ParsedJwt, issuer: string, ...requirements: string[]): void {
	const c: Condition = condition("ValidateRequestObjectAud", ...requirements);
	if (!Object.hasOwn(requestObject.claims, "aud")) {
		c.failure("Missing audience, request object does not contain an 'aud' claim");
	}
	const aud = requestObject.claims["aud"];
	if (Array.isArray(aud)) {
		if (!aud.includes(issuer)) {
			c.failure("aud claim values does not include the suite's issuer identifier", { expected: issuer, actual: aud });
		}
	} else if (issuer !== str(requestObject.claims, "aud")) {
		c.failure("aud claim value does not match the suite's issuer identifier", { expected: issuer, actual: aud });
	}
	c.success("aud claim matches the suite's issuer identifier", { aud });
}

function recordFailedKey(failedKeys: Record<string, unknown>[], jwk: JWK, reason: string): void {
	const entry: Record<string, unknown> = { kid: (jwk["kid"] as string | undefined) ?? null };
	if (jwk["kty"] != null) {
		entry["kty"] = jwk["kty"];
	}
	entry["reason"] = reason;
	failedKeys.push(entry);
}

/**
 * Verifies the request object's signature with a key of the client's JWKS (the client's registered
 * request_object_signing_alg must be used). Returns the algorithm (upstream "request_object_signing_alg").
 *
 * upstream: condition/as/ValidateRequestObjectSignature.java
 */
export async function validateRequestObjectSignature(
	requestObject: ParsedJwt,
	clientPublicJwks: Jwks,
	client: RpClient,
	...requirements: string[]
): Promise<string> {
	const c: Condition = condition("ValidateRequestObjectSignature", ...requirements);
	const value = requestObject.value;
	try {
		const jwt = parseSignedJWT(value);
		// parse leniently: skip keys the JOSE library cannot handle so an unusable key elsewhere in the client's set
		// does not abort verification when a usable signing key is present; skipped keys are logged
		const jwkSet = parseJwksLenientlyLoggingSkips(c, clientPublicJwks, "client");
		const headerAlg = jwt.header["alg"] as string;
		if (client["request_object_signing_alg"] !== undefined) {
			// All Request Objects from this Client MUST be rejected, if not signed with this algorithm.
			const expectedAlg = str(client, "request_object_signing_alg");
			if (headerAlg !== expectedAlg) {
				c.failure("Algorithm in JWT header does not match client request_object_signing_alg.", {
					actual: headerAlg,
					expected: expectedAlg,
				});
			}
		}
		const jwkKeys = selectJWSJwks(jwt.header, jwkSet);
		if (jwkKeys == null || jwkKeys.length === 0) {
			c.failure("Could not find any keys that can be used to verify this signature", {
				requestObject: value,
				clientJwks: clientPublicJwks,
			});
		}
		const publicJwks = getPublicJwksAsJsonObject({ keys: jwkKeys });
		// why each candidate key did not verify, only reported if no key works
		const failedKeys: Record<string, unknown>[] = [];
		for (const jwkKey of jwkKeys) {
			let verifier: JWSVerifier | null = null;
			try {
				if (jwkKey["kty"] === "OKP") {
					const publicKey = toPublicJWK(jwkKey) as JWK;
					if (publicKey["crv"] === "Ed25519") {
						verifier = {
							jwk: publicKey,
							key: await importKey(publicKey, headerAlg === "Ed25519" ? "Ed25519" : "EdDSA"),
						};
					} else {
						recordFailedKey(
							failedKeys,
							jwkKey,
							"the JOSE library cannot verify with this key's curve ('" + String(publicKey["crv"]) + "')",
						);
					}
				} else if (jwkKey["kty"] === "RSA" || jwkKey["kty"] === "EC") {
					const publicKey = toPublicJWK(jwkKey) as JWK;
					// like Nimbus' ECDSAVerifier, an EC key is bound to the algorithm of its curve
					const keyAlg =
						publicKey["kty"] === "EC" ? (EC_CURVE_ALGORITHM[publicKey["crv"] as string] ?? headerAlg) : headerAlg;
					verifier = { jwk: publicKey, key: await importKey(publicKey, keyAlg) };
				} else if (jwkKey["kty"] === "oct") {
					const secretKey = (await importKey(jwkKey, headerAlg)) as Uint8Array;
					if (secretKey.length * 8 < 256) {
						throw new JOSEException("The secret length must be at least 256 bits");
					}
					verifier = { jwk: jwkKey, key: secretKey };
				}
			} catch (e) {
				// reported like Nimbus failing to build a verifier
				recordFailedKey(
					failedKeys,
					jwkKey,
					"the JOSE library could not build a verifier for this key: " + (e as Error).message,
				);
			}
			if (verifier != null) {
				if (await verifySignedJWT(jwt, verifier)) {
					c.success(
						"Request object signature validated using a key in the client's JWKS " +
							"and using the client's registered request_object_signing_alg",
						{
							request_object_signing_alg: headerAlg,
							jwk: JSON.stringify(jwkKey),
							keys: publicJwks,
							request_object: value,
						},
					);
					return headerAlg;
				}
				// failed to verify with this key, moving on - it might pass with a different key
				recordFailedKey(failedKeys, jwkKey, "the signature did not verify with this key");
			}
		}
		c.failure("Unable to verify request object signature based on client keys", {
			jwt_header: JSON.stringify(jwt.header),
			keys: publicJwks,
			failed_keys: failedKeys,
			clientJwks: clientPublicJwks,
			requestObject: value,
		});
	} catch (e) {
		if (e instanceof JOSEException || e instanceof ParseException) {
			c.failureFrom("error validating request object signature", e);
		}
		throw e;
	}
}

/**
 * OIDCC 6.1 / 6.2: response_type and client_id must also be plain request parameters, and match the request
 * object's values when it has them. scope need not match.
 *
 * upstream: condition/as/EnsureRequiredAuthorizationRequestParametersMatchRequestObject.java
 */
export function ensureRequiredAuthorizationRequestParametersMatchRequestObject(
	params: AuthorizationParams,
	requestObject: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureRequiredAuthorizationRequestParametersMatchRequestObject", ...requirements);
	const failures: Record<string, unknown> = {};
	const successes: Record<string, unknown> = {};
	for (const name of PARAMETERS_THAT_MUST_MATCH) {
		const fromHttpRequest = params[name];
		const fromRequestObject = requestObject.claims[name];
		if (fromHttpRequest === undefined) {
			// unlikely, another condition will probably fail before this one
			failures[name] = `Required parameter '${name}' was not found in http request parameters`;
		} else if (fromRequestObject === undefined) {
			successes[name] = "Not found in request object";
		} else if (!isDeepStrictEqual(fromHttpRequest, fromRequestObject)) {
			failures[name] = { "Value in http request": fromHttpRequest, "Value in request object": fromRequestObject };
		} else {
			successes[name] = fromHttpRequest;
		}
	}
	if (Object.keys(failures).length === 0) {
		c.success("Required http request parameters match request object claims", successes);
		return;
	}
	c.failure("Required http request parameters and request object claims must match", failures);
}

const PARAMETERS_THAT_MUST_MATCH = ["response_type", "client_id"];

/** For an encrypted request object (use with a skip without jwe_header). upstream: condition/as/ValidateEncryptedRequestObjectHasKid.java */
export function validateEncryptedRequestObjectHasKid(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("ValidateEncryptedRequestObjectHasKid", ...requirements);
	const jweHeader = requestObject.jwe_header ?? {};
	const alg = str(jweHeader, "alg");
	if (isSymmetricJWEAlgorithm(alg)) {
		c.success("skipping KID check for symmetric alg " + alg);
		return;
	}
	const kid = str(jweHeader, "kid");
	if (!kid) {
		c.failure("kid was not found in the encrypted request object header");
	}
	c.success("kid was found in the encrypted request object header", { kid });
}

/** Only logs a WARNING. upstream: condition/as/EnsureOptionalAuthorizationRequestParametersMatchRequestObject.java */
export function ensureOptionalAuthorizationRequestParametersMatchRequestObject(
	params: AuthorizationParams,
	requestObject: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureOptionalAuthorizationRequestParametersMatchRequestObject", ...requirements);
	const claims = requestObject.claims;
	const differences: Record<string, unknown> = {};
	for (const name of Object.keys(params)) {
		if (PARAMETERS_THAT_MUST_MATCH.includes(name)) {
			// already checked
			continue;
		}
		if (!Object.hasOwn(claims, name)) {
			continue;
		}
		// scope=openid in the http request is not reported, only other differing scope values
		if (name === "scope" && str(params, name) === "openid") {
			continue;
		}
		if (!isDeepStrictEqual(params[name], claims[name])) {
			differences[name] = { "Value in http request": params[name], "Value in request object": claims[name] };
		}
	}
	if (Object.keys(differences).length === 0) {
		c.success("All http request parameters and request object claims match");
		return;
	}
	c.failure(
		"Some http request parameters and request object claims do not match. " +
			"This is allowed but you should check if the differences are intentional",
		differences,
	);
}

/** https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#parameters */
const EXPECTED_AUTH_REQUEST_PARAMS = [
	// RFC6749
	"client_id",
	"redirect_uri",
	"response_type",
	"state",
	"scope",
	// OpenID Connect Core
	"acr_values",
	"claims",
	"claims_locales",
	"display",
	"id_token_hint",
	"login_hint",
	"max_age",
	"nonce",
	"prompt",
	"registration",
	"request",
	"request_uri",
	"ui_locales",
	// RFC7636
	"code_challenge",
	"code_challenge_method",
	// OAuth 2.0 Multiple Response Type Encoding Practices
	"response_mode",
	// RFC7519 4.1
	"aud",
	"exp",
	"nbf",
	"iat",
	"iss",
	"jti",
	"sub",
	// DPoP
	"dpop_jkt",
	// RFC8485
	"vtr",
	// RFC8707
	"resource",
	// RFC9396
	"authorization_details",
	// ConnectID purpose
	"purpose",
	// Grant Management
	"grant_management_action",
	"grant_id",
];

/** RFC9101 section 4: authorization endpoint parameters not expected in the request object */
const PARAMS_NOT_EXPECTED_FOR_REQUEST_OBJECT = ["request", "request_uri"];

/** upstream: condition/as/CheckForUnexpectedClaimsInRequestObject.java */
export function checkForUnexpectedClaimsInRequestObject(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("CheckForUnexpectedClaimsInRequestObject", ...requirements);
	const claims = Object.keys(requestObject.claims);
	const unknown = claims.filter(
		(claim) => !EXPECTED_AUTH_REQUEST_PARAMS.includes(claim) || PARAMS_NOT_EXPECTED_FOR_REQUEST_OBJECT.includes(claim),
	);
	if (unknown.length === 0) {
		c.success("all authorization_request_object claims are expected", { claims });
		return;
	}
	c.failure("unknown claims found in authorization_request_object", { claims, unknown_claims: unknown });
}

// ---------------------------------------------------------------------------------------------------------------
// the request_uri modules

/** upstream: condition/as/EnsureRequestObjectWasSignedWithNone.java */
export function ensureRequestObjectWasSignedWithNone(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("EnsureRequestObjectWasSignedWithNone", ...requirements);
	const alg = str(requestObject.header, "alg");
	if (alg === "none") {
		c.success("Request object was signed using algorithm 'none'");
		return;
	}
	c.failure("Request object must be signed with algorithm 'none'", { actual: alg });
}

/** upstream: condition/as/EnsureRequestObjectWasSignedWithRS256.java */
export function ensureRequestObjectWasSignedWithRS256(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("EnsureRequestObjectWasSignedWithRS256", ...requirements);
	const alg = str(requestObject.header, "alg");
	if (alg === "RS256") {
		c.success("Request object was signed using RS256 algorithm");
		return;
	}
	c.failure("Request object must be signed with RS256", { actual: alg });
}

// ---------------------------------------------------------------------------------------------------------------
// the checks of the authorization endpoint

/**
 * The checks on the request object's claims and signature, then the module's own (`checkRequestObject`). An
 * unsigned request object (alg none) is allowed and not checked for iss, aud or signature.
 *
 * upstream: AbstractOIDCCClientTest.validateRequestObject (allowUnsignedRequestObjects() is true)
 */
export async function validateRequestObject(op: EmulatedOp, requestObject: ParsedJwt): Promise<void> {
	const client = op.client as RpClient;
	if (requestObject.claims["exp"] == null) {
		skipped(
			"OIDCCValidateRequestObjectExp",
			{ element: ["authorization_request_object", "claims.exp"] },
			"RFC7519-4.1.4",
		);
	} else {
		soft(() => oidccValidateRequestObjectExp(requestObject, "RFC7519-4.1.4"));
	}
	soft(() => validateRequestObjectIat(requestObject, "OIDCC-6.1"), "warning");
	soft(() => ensureNumericRequestObjectClaimsAreNotNull(requestObject, "OIDCC-13.3"), "warning");
	soft(() => validateRequestObjectMaxAge(requestObject, "OIDCC-13.3"));
	soft(() => ensureRequestObjectDoesNotContainRequestOrRequestUri(requestObject, "OIDCC-6.1"), "warning");
	soft(() => ensureRequestObjectDoesNotContainSubWithClientId(requestObject, client, "JAR-10.8"), "warning");
	if (requestObject.header["alg"] !== "none") {
		// If signed, the Request Object SHOULD contain the Claims iss (the client) and aud (the OP's issuer)
		soft(() => validateRequestObjectIss(requestObject, client, "OIDCC-6.1"), "warning");
		soft(() => validateRequestObjectAud(requestObject, op.metadata.issuer as string, "OIDCC-6.1"), "warning");
		// without request_object_signing_alg the client need not have keys: the signature cannot be verified then
		if (op.clientPublicJwks == null) {
			currentLog().log("ValidateRequestObjectSignature", {
				msg: "Skipped evaluation due to missing required object: client_public_jwks",
				expected: "client_public_jwks",
				result: "FAILURE",
				requirements: ["OIDCC-6.1"],
			});
		} else {
			const jwks = op.clientPublicJwks;
			await soft(() => validateRequestObjectSignature(requestObject, jwks, client, "OIDCC-6.1"));
		}
	}
	op.options.checkRequestObject?.(requestObject);
}

/**
 * The request object against the plain request parameters: the claims and signature ({@link validateRequestObject}),
 * response_type / client_id match, an encrypted one has a kid, the other parameters match (warning).
 *
 * upstream: AbstractOIDCCClientTest.extractAuthorizationEndpointRequestParameters (the request object part after
 * EnsureAuthorizationHttpRequestContainsOpenIDScope)
 */
export async function checkRequestObject(
	op: EmulatedOp,
	params: AuthorizationParams,
	requestObject: ParsedJwt,
): Promise<void> {
	await validateRequestObject(op, requestObject);
	ensureRequiredAuthorizationRequestParametersMatchRequestObject(params, requestObject, "OIDCC-6.1", "OIDCC-6.2");
	if (requestObject.jwe_header == null) {
		skipped(
			"ValidateEncryptedRequestObjectHasKid",
			{ element: ["authorization_request_object", "jwe_header"] },
			"OIDCC-10.2",
			"OIDCC-10.2.1",
		);
	} else {
		soft(() => validateEncryptedRequestObjectHasKid(requestObject, "OIDCC-10.2", "OIDCC-10.2.1"));
	}
	soft(
		() =>
			ensureOptionalAuthorizationRequestParametersMatchRequestObject(params, requestObject, "OIDCC-6.1", "OIDCC-6.2"),
		"warning",
	);
}

// ---------------------------------------------------------------------------------------------------------------
// the FAPI 2 checks on a signed request object (upstream AbstractFAPI2SPFinalClientTest.validateRequestObjectCommonChecks)

/** upstream: condition/as/FAPI2ValidateRequestObjectSigningAlg.java */
export function fapi2ValidateRequestObjectSigningAlg(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("FAPI2ValidateRequestObjectSigningAlg", ...requirements);
	const alg = str(requestObject.header, "alg");
	if (alg != null && FAPI2_ALLOWED_ALGS.includes(alg)) {
		c.success("Request object was signed with a permitted algorithm", { alg });
		return;
	}
	c.failure("Request object must be signed with PS256, ES256, EdDSA, or Ed25519", { alg });
}

/** upstream: condition/as/FAPIValidateRequestObjectMediaType.java */
export function fapiValidateRequestObjectMediaType(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("FAPIValidateRequestObjectMediaType", ...requirements);
	const typ = str(requestObject.header, "typ");
	if (typ == null) {
		c.success("Request object media type was not specified");
		return;
	}
	if (typ.toLowerCase() === "oauth-authz-req+jwt") {
		c.success("Request object media type is valid", { typ });
		return;
	}
	c.failure("Request object media type is not as expected", { expected: "oauth-authz-req+jwt", typ });
}

/**
 * The acr values the request object's claims parameter asks for in the id_token (claims.id_token.acr): the ones
 * among the Open Banking UK values, as a JSON array string (upstream "requested_id_token_acr_values"), or null when
 * none is requested.
 *
 * upstream: condition/client/FAPIValidateRequestObjectIdTokenACRClaims.java
 */
export function fapiValidateRequestObjectIdTokenACRClaims(
	requestObject: ParsedJwt,
	...requirements: string[]
): string | null {
	const c: Condition = condition("FAPIValidateRequestObjectIdTokenACRClaims", ...requirements);
	const claimsParam = requestObject.claims["claims"];
	const idTokenClaims =
		claimsParam != null && typeof claimsParam === "object" && !Array.isArray(claimsParam)
			? (claimsParam as Record<string, unknown>)["id_token"]
			: null;
	const acrClaim =
		idTokenClaims != null && typeof idTokenClaims === "object" && !Array.isArray(idTokenClaims)
			? (idTokenClaims as Record<string, unknown>)["acr"]
			: null;
	if (acrClaim == null) {
		c.success("acr claim not requested");
		return null;
	}
	if (typeof acrClaim !== "object" || Array.isArray(acrClaim)) {
		c.failure("The acr claim is not a JsonObject", { acrClaim });
	}
	const acr = acrClaim as Record<string, unknown>;
	if (Object.hasOwn(acr, "essential") && typeof acr["essential"] !== "boolean") {
		c.failure("the 'essential' value is not a boolean", { essential: acr["essential"] });
	}
	// https://openid.net/specs/openid-connect-core-1_0.html#acrSemantics
	let receivedValues: string[];
	if (Object.hasOwn(acr, "values")) {
		const acrValues = acr["values"];
		if (acrValues == null || !Array.isArray(acrValues)) {
			c.failure("Acr values is missing or is not an array in request object", { received: acrValues ?? null });
		}
		receivedValues = acrValues.map(String);
	} else if (Object.hasOwn(acr, "value")) {
		const acrValue = acr["value"];
		if (acrValue == null) {
			c.failure("Acr values is null in request object", { acrClaim });
		}
		receivedValues = [getString(acrValue)];
	} else {
		c.success("acr claim does not request any values");
		return null;
	}
	const expectedValues = ["urn:openbanking:psd2:sca", "urn:openbanking:psd2:ca"];
	const matchedAcrValues = receivedValues.filter((v) => expectedValues.includes(v));
	if (matchedAcrValues.length > 0) {
		c.success("Acr value in request object is as expected", { received: matchedAcrValues });
		return JSON.stringify(matchedAcrValues);
	}
	c.failure("An acr value in the request object does not match one of the expected values", {
		received: matchedAcrValues,
		expected: expectedValues,
	});
}

/** upstream: condition/as/FAPIValidateRequestObjectExp.java */
export function fapiValidateRequestObjectExp(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("FAPIValidateRequestObjectExp", ...requirements);
	const now = Date.now();
	const sixtyMinutesMillis = 60 * 60 * 1000;
	const exp = long(requestObject.claims, "exp");
	if (exp == null) {
		c.failure("Missing exp, request object does not contain an 'exp' claim");
	}
	if (now - TIME_SKEW_MILLIS > exp * 1000) {
		c.failure("Token expired", { exp: new Date(exp * 1000).toISOString(), now: new Date(now).toISOString() });
	}
	if (now + sixtyMinutesMillis < exp * 1000) {
		c.failure("Request object expires unreasonably far in the future", {
			exp: new Date(exp * 1000).toISOString(),
			now: new Date(now).toISOString(),
		});
	}
	c.success("Request object contains a valid exp claim, expiry time", { exp: new Date(exp * 1000).toISOString() });
}

/** The nbf claim is present and not more than 60 minutes in the past. upstream: condition/as/FAPI1AdvancedValidateRequestObjectNBFClaim.java */
export function fapi1AdvancedValidateRequestObjectNBFClaim(requestObject: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("FAPI1AdvancedValidateRequestObjectNBFClaim", ...requirements);
	const sixtyMinutes = 60 * 60 * 1000;
	const now = Date.now();
	const nbf = long(requestObject.claims, "nbf");
	if (nbf == null) {
		c.failure("Missing nbf claim in request object");
	}
	const nbfMillis = nbf * 1000;
	if (nbfMillis < now - sixtyMinutes) {
		c.failure("nbf claim is more than 60 minutes in the past", {
			nbf: new Date(nbfMillis).toISOString(),
			now: new Date(now).toISOString(),
		});
	}
	if (nbfMillis > now + TIME_SKEW_MILLIS) {
		c.failure("nbf claim is in the future", {
			nbf: new Date(nbfMillis).toISOString(),
			now: new Date(now).toISOString(),
			time_skew: TIME_SKEW_MILLIS,
		});
	}
	c.success("nbf claim is valid", { nbf: new Date(nbfMillis).toISOString(), now: new Date(now).toISOString() });
}

/**
 * iss is the client_id, aud the issuer, exp / iat / nbf plausible, jti a string when present.
 *
 * upstream: condition/as/ValidateRequestObjectClaims.java
 */
export function validateRequestObjectClaims(requestObject: ParsedJwt, client: RpClient, issuer: string): void {
	const c: Condition = condition("ValidateRequestObjectClaims");
	const clientId = client.client_id;
	const now = Date.now();
	// check all our testable values
	if (!clientId || !issuer) {
		c.failure("Couldn't find values to test request object against");
	}
	const iss = str(requestObject.claims, "iss");
	if (iss == null) {
		c.failure("Missing issuer");
	}
	if (clientId !== iss) {
		c.failure("Issuer mismatch", { expected: clientId, actual: iss });
	}
	// validateAud
	const aud = requestObject.claims["aud"];
	if (aud == null) {
		c.failure("Missing audience");
	}
	if (Array.isArray(aud)) {
		if (!aud.includes(issuer)) {
			c.failure("Audience not found", { expected: issuer, actual: aud });
		}
	} else if (issuer !== getString(aud)) {
		c.failure("Audience mismatch", { expected: issuer, actual: aud });
	}
	const exp = long(requestObject.claims, "exp");
	if (exp == null) {
		c.log({ msg: "Missing expiration", result: "INFO" });
	} else {
		if (now - TIME_SKEW_MILLIS > exp * 1000) {
			c.failure("Token expired", { expiration: new Date(exp * 1000).toISOString(), now: new Date(now).toISOString() });
		}
		if (exp * 1000 > now + 50 * 365 * 24 * 60 * 60 * 1000) {
			c.failure(
				"'exp' is unreasonably far in the future (more than 50 years), this may indicate the value was incorrectly specified in milliseconds instead of seconds",
				{ exp: new Date(exp * 1000).toISOString(), now: new Date(now).toISOString() },
			);
		}
	}
	// validateIat
	const iat = long(requestObject.claims, "iat");
	if (iat == null) {
		c.log({ msg: "Missing issuance time", result: "INFO" });
	} else {
		if (now + TIME_SKEW_MILLIS < iat * 1000) {
			c.failure("Token issued in the future", {
				"issued-at": new Date(iat * 1000).toISOString(),
				now: new Date(now).toISOString(),
			});
		}
		if (now - 24 * 60 * 60 * 1000 > iat * 1000) {
			c.failure("'iat' is more than 1 day in the past", {
				"issued-at": new Date(iat * 1000).toISOString(),
				now: new Date(now).toISOString(),
			});
		}
	}
	const nbf = long(requestObject.claims, "nbf");
	if (nbf != null && now + TIME_SKEW_MILLIS < nbf * 1000) {
		// this is just something to log, it doesn't make the token invalid
		c.log("Token has future not-before", {
			"not-before": new Date(nbf * 1000).toISOString(),
			now: new Date(now).toISOString(),
		});
	}
	// validateJti
	const jti = requestObject.claims["jti"];
	if (jti != null && typeof jti !== "string") {
		c.failure("jti must be a string when present", { jti });
	}
	c.success("Request object claims passed all validation checks");
}

/** The request object's redirect_uri is the configured client's. upstream: condition/as/EnsureMatchingRedirectUriInRequestObject.java */
export function ensureMatchingRedirectUriInRequestObject(requestObject: ParsedJwt, client: RpClient): void {
	const c: Condition = condition("EnsureMatchingRedirectUriInRequestObject");
	const expected = typeof client["redirect_uri"] === "string" ? client["redirect_uri"] : null;
	const actual = str(requestObject.claims, "redirect_uri");
	if (expected && expected === actual) {
		c.success("Redirect URI matched", { actual: actual ?? "" });
		return;
	}
	c.failure("Mismatch between redirect URI", { expected: expected ?? "", actual: actual ?? "" });
}

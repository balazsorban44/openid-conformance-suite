/**
 * JARM (JWT Secured Authorization Response Mode): the `response` JWT in the redirect_uri query, its claims as the
 * authorization response, and the checks on it.
 *
 *   const jarm = await jarm.extractJARMFromURLQuery(response, client);
 *   response.params = jarm.extractAuthorizationEndpointResponseFromJARMResponse(jarm);
 *   soft(() => jarm.validateJARMResponse(op, client.client, jarm, "JARM-2.4-2", ...));
 */
import { condition, type Condition } from "../suite/conditions.ts";
import {
	JOSEException,
	ParseException,
	parseJwt,
	verifyJwsSignature,
	type Jwks,
	type ParsedJwt,
} from "../suite/jose.ts";
import type { AuthorizationResponse } from "./authorization.ts";
import type { ServerMetadata } from "./discovery.ts";
import type { Client, ClientKeys } from "./registration.ts";
import { verifyJweEncryption } from "./token.ts";

/** The FAPI 2.0 signing algorithms (upstream FAPI2CheckDiscEndpointIdTokenSigningAlgValuesSupported.FAPI2_ALLOWED_ALGS) */
export const FAPI2_ALLOWED_ALGS: readonly string[] = ["PS256", "ES256", "EdDSA", "Ed25519"];

/** upstream: condition/client/ValidateJARMFromURLQueryEncryption.java (AbstractVerifyJweEncryption) */
export function validateJARMFromURLQueryEncryption(
	response: Pick<AuthorizationResponse, "query">,
	clientJwks: Jwks,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateJARMFromURLQueryEncryption", ...requirements);
	const jarm = response.query["response"];
	if (jarm == null || typeof jarm === "object") {
		c.failure("Couldn't find response in callback_query_params");
	}
	if (verifyJweEncryption(c, String(jarm), clientJwks, "response")) {
		c.success("The client has a valid asymmetric key to decrypt the respose");
	} else {
		c.success("The response is not encrypted using an asymmetric encryption algorithm");
	}
}

/**
 * Parses (decrypting with the client's keys if needed) the JARM response of the redirect_uri query.
 *
 * upstream: condition/client/ExtractJARMFromURLQuery.java (AbstractExtractJWT)
 */
export async function extractJARMFromURLQuery(
	response: Pick<AuthorizationResponse, "query">,
	client: { client: Client; keys: ClientKeys | null },
	...requirements: string[]
): Promise<ParsedJwt> {
	const c: Condition = condition("ExtractJARMFromURLQuery", ...requirements);
	const key = "callback_query_params";
	const dstPath = "jarm_response";
	const token = response.query["response"];
	if (token == null || typeof token === "object") {
		c.failure("Couldn't find response in " + key);
	}
	try {
		const parsed = await parseJwt(String(token), client.client, client.keys?.jwks ?? null);
		if (parsed == null) {
			c.failure("Couldn't parse " + dstPath + " from " + key + " as a JWT", { [dstPath]: token });
		}
		c.success("Found and parsed the " + dstPath + " from " + key, { ...parsed });
		return parsed;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse " + dstPath + " from " + key + " as a JWT", e, { [dstPath]: token });
		}
		if (
			e instanceof JOSEException ||
			(e as Error).name?.startsWith("JOSE") ||
			(e as { code?: string }).code?.startsWith("ERR_J")
		) {
			c.failureFrom("Decrypting " + dstPath + " from " + key + " failed", e, { [dstPath]: token });
		}
		throw e;
	}
}

/** upstream: condition/client/RejectNonJarmResponsesInUrlQuery.java */
export function rejectNonJarmResponsesInUrlQuery(
	response: Pick<AuthorizationResponse, "query">,
	redirectUri: string,
	...requirements: string[]
): void {
	const c: Condition = condition("RejectNonJarmResponsesInUrlQuery", ...requirements);
	const params = { ...response.query };
	delete params["response"];
	// ignore items we require to be in the registered redirect url query for the second client
	for (const name of new URL(redirectUri).searchParams.keys()) {
		delete params[name];
	}
	if (Object.keys(params).length > 0) {
		c.failure(
			"When using JARM, The authorization endpoint response should only contain 'response' containing a JWT.",
			params,
		);
	}
	c.success("Authorization endpoint response only includes the JARM JWT.");
}

/**
 * The authorization response carried by the JARM JWT: its claims without the standard JWT claims (RFC 7519 4.1),
 * iss excepted (it is also the response's iss parameter).
 *
 * upstream: condition/client/ExtractAuthorizationEndpointResponseFromJARMResponse.java
 */
export function extractAuthorizationEndpointResponseFromJARMResponse(jarm: ParsedJwt): Record<string, unknown> {
	const jwtClaims = [/* "iss", */ "sub", "aud", "exp", "nbf", "iat", "jti"];
	const authResponse = structuredClone(jarm.claims);
	for (const claim of jwtClaims) {
		delete authResponse[claim];
	}
	condition("ExtractAuthorizationEndpointResponseFromJARMResponse").success("Extracted the authorization response", {
		...authResponse,
	});
	return authResponse;
}

/** java.util.Date.toString() of an epoch second (what upstream logs for the JARM timestamps) */
function dateString(seconds: number): string {
	return new Date(seconds * 1000).toString();
}

function longClaim(jarm: ParsedJwt, name: string): number | null {
	const v = jarm.claims[name];
	return typeof v === "number" ? Math.trunc(v) : null;
}

/** upstream: condition/client/ValidateJARMResponse.java */
export function validateJARMResponse(
	op: { metadata: Pick<ServerMetadata, "issuer"> },
	client: Pick<Client, "client_id">,
	jarm: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateJARMResponse", ...requirements);
	const timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing
	const clientId = client.client_id; // to check the audience
	const issuer = op.metadata.issuer; // to validate the issuer
	const now = Date.now(); // to check timestamps
	if (!clientId || !issuer) {
		c.failure("Couldn't find values to test response against");
	}
	const iss = jarm.claims["iss"];
	if (iss == null) {
		c.failure("Missing issuer");
	}
	if (issuer !== iss) {
		c.failure("Issuer mismatch", { expected: issuer, actual: typeof iss === "string" ? iss : null });
	}
	const aud = jarm.claims["aud"];
	if (aud == null) {
		c.failure("Missing audience");
	}
	if (Array.isArray(aud)) {
		if (!aud.includes(clientId)) {
			c.failure("Audience not found", { expected: clientId, actual: aud });
		}
	} else if (clientId !== aud) {
		c.failure("Audience mismatch", { expected: clientId, actual: aud });
	}
	const exp = longClaim(jarm, "exp");
	if (exp == null) {
		c.failure("Missing expiration");
	}
	if (now - timeSkewMillis > exp * 1000) {
		c.failure("Token expired", { expiration: dateString(exp), now: new Date(now).toISOString() });
	}
	if (exp * 1000 > now + 50 * 365 * 24 * 60 * 60 * 1000) {
		c.failure(
			"'exp' is unreasonably far in the future (more than 50 years), this may indicate the value was incorrectly specified in milliseconds instead of seconds",
			{ exp: dateString(exp), now: new Date(now).toISOString() },
		);
	}
	// iat and nbf are not required to be present, but should be valid if they are
	// https://bitbucket.org/openid/fapi/issues/269/jarm-response-contents-clarifications
	const iat = longClaim(jarm, "iat");
	if (iat != null) {
		if (now + timeSkewMillis < iat * 1000) {
			c.failure("Token issued in the future", { "issued-at": dateString(iat), now: new Date(now).toISOString() });
		}
		if (now - 24 * 60 * 60 * 1000 > iat * 1000) {
			c.failure("'iat' is more than 1 day in the past", {
				"issued-at": dateString(iat),
				now: new Date(now).toISOString(),
			});
		}
	}
	const nbf = longClaim(jarm, "nbf");
	if (nbf != null && now + timeSkewMillis < nbf * 1000) {
		// this is just something to log, it doesn't make the token invalid
		c.log("Token has future not-before", { "not-before": dateString(nbf), now: new Date(now).toISOString() });
	}
	c.success("JARM response standard JWT claims are valid");
}

/** upstream: condition/client/FAPI2ValidateJarmSigningAlg.java */
export function fapi2ValidateJarmSigningAlg(jarm: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("FAPI2ValidateJarmSigningAlg", ...requirements);
	const alg = jarm.header["alg"];
	const permitted = [...FAPI2_ALLOWED_ALGS];
	if (typeof alg === "string" && permitted.includes(alg)) {
		c.success("JARM response was signed with a permitted algorithm", { alg, permitted });
		return;
	}
	c.failure("JARM response must be signed with a permitted alg", { alg, permitted });
}

/**
 * upstream: condition/client/ValidateJARMSigningAlg.java
 *
 * UPSTREAM: reads `jarm_response.jws_header.alg`, a member JWTUtil never sets, so upstream's
 * `skipIfElementMissing("jarm_response", "jws_header", ...)` always skips this check: callers log the skip.
 */
export function validateJARMSigningAlg(
	op: { metadata: ServerMetadata },
	jarm: ParsedJwt & { jws_header?: Record<string, unknown> },
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateJARMSigningAlg", ...requirements);
	const alg = jarm.jws_header?.["alg"] ?? null;
	const supported = op.metadata["authorization_signing_alg_values_supported"];
	if (supported != null) {
		if (Array.isArray(supported) && supported.includes(alg)) {
			c.success(
				"JARM response was signed with a supported algorithmThe JWS header 'alg' matched an entry in the 'authorization_signing_alg_values_supported' array returned in the server's discovery document",
				{ alg, supported },
			);
			return;
		}
		c.failure(
			"JARM response must be signed with an encryption algorithm listed in 'authorization_signing_alg_values_supported' returned in the server's discovery document",
			{ alg, supported },
		);
	}
	c.failure(
		"No JARM response signing algorithms found. 'authorization_signing_alg_values_supported' is not present in the server's discovery document",
	);
}

/** upstream: condition/client/ValidateJARMEncryptionAlg.java */
export function validateJARMEncryptionAlg(
	op: { metadata: ServerMetadata },
	jarm: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateJARMEncryptionAlg", ...requirements);
	const alg = jarm.jwe_header?.["alg"] ?? null;
	const supported = op.metadata["authorization_encryption_alg_values_supported"];
	if (supported != null) {
		if (Array.isArray(supported) && supported.includes(alg)) {
			c.success(
				"JARM response CEK was encrypted with a supported algorithmThe JWE header 'alg' matched an entry in the 'authorization_encryption_enc_values_supported' array returned in the server's discovery document",
				{ alg, supported },
			);
			return;
		}
		c.failure(
			"JARM response CEK must be encrypted with an encryption algorithm listed in 'authorization_encryption_alg_values_supported' returned in the server's discovery document",
			{ alg, supported },
		);
	}
	c.failure(
		"No JARM CEK response encryption algorithms found. 'authorization_encryption_alg_values_supported' is not present in the server's discovery document",
	);
}

/** upstream: condition/client/ValidateJARMEncryptionEnc.java */
export function validateJARMEncryptionEnc(
	op: { metadata: ServerMetadata },
	jarm: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateJARMEncryptionEnc", ...requirements);
	const enc = jarm.jwe_header?.["enc"] ?? null;
	const supported = op.metadata["authorization_encryption_enc_values_supported"];
	if (supported != null) {
		if (Array.isArray(supported) && supported.includes(enc)) {
			c.success(
				"JARM response Plaintext was encrypted with a supported encryption method.The JWE header 'enc' matched an entry in the 'authorization_encryption_enc_values_supported' array returned in the server's discovery document",
				{ enc, supported },
			);
			return;
		}
		c.failure(
			"JARM response Plaintext must be encrypted with an encryption method listed in 'authorization_encryption_enc_values_supported' returned in the server's discovery document",
			{ enc, supported },
		);
	}
	c.failure(
		"No JARM response Plaintext encryption methods found. 'authorization_encryption_enc_values_supported' is not present in the server's discovery document",
	);
}

/** upstream: condition/client/ValidateJARMExpRecommendations.java */
export function validateJARMExpRecommendations(jarm: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("ValidateJARMExpRecommendations", ...requirements);
	const timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing
	const now = Date.now();
	const exp = longClaim(jarm, "exp");
	if (exp == null) {
		c.failure("'exp' claim missing from JARM response");
	}
	// exp recommended to be less than 10 minutes - added after JARM ID1:
	// https://bitbucket.org/openid/fapi/commits/8ac0bc6059cfcfdb6c155efa2d992a1eb86e8b6c -
	const allowableLifeTimeMinutes = 10;
	if (now + timeSkewMillis + allowableLifeTimeMinutes * 60 * 1000 < exp * 1000) {
		c.failure(
			"JARM 'exp' time is further in the future than the recommended " + allowableLifeTimeMinutes + " minutes",
			{
				expiration: dateString(exp),
				now: new Date(now).toISOString(),
			},
		);
	}
	// not mentioned by spec, but for the sake of sanity check the response has a lifetime of at least 10 seconds or
	// it's likely to fall in various real world situations. We don't use 'timeSkewMillis' here, as that would allow a
	// zero expiry to pass
	const minimumLifeTimeSeconds = 10;
	if (now + minimumLifeTimeSeconds * 1000 > exp * 1000) {
		c.failure("JARM 'exp' time appears to be less than " + minimumLifeTimeSeconds + " seconds", {
			expiration: dateString(exp),
			now: new Date(now).toISOString(),
		});
	}
	c.success("JARM response 'exp' is less than " + allowableLifeTimeMinutes + " minutes", {
		expiration: dateString(exp),
		now: new Date(now).toISOString(),
	});
}

/** upstream: condition/client/ValidateJARMSignatureUsingKid.java (AbstractVerifyJwsSignature) */
export async function validateJARMSignatureUsingKid(
	jarm: ParsedJwt,
	serverJwks: Jwks,
	...requirements: string[]
): Promise<void> {
	const c: Condition = condition("ValidateJARMSignatureUsingKid", ...requirements);
	await verifyJwsSignature(c, jarm.value, serverJwks, "jarm_response", true, "server");
}

/**
 * The plain (non-JARM) error response the OP sent instead of a JARM response is the authorization response.
 *
 * upstream: condition/client/AddPlainErrorResponseAsAuthorizationEndpointResponseForJARM.java
 */
export function addPlainErrorResponseAsAuthorizationEndpointResponseForJARM(
	response: Pick<AuthorizationResponse, "query">,
): Record<string, unknown> {
	condition("AddPlainErrorResponseAsAuthorizationEndpointResponseForJARM").success(
		"The server returned a plain error response instead of a JARM response",
		{ ...response.query },
	);
	return response.query;
}

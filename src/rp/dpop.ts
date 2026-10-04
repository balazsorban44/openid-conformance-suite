/**
 * DPoP (RFC 9449) at the emulated authorization and resource server: the proof the RP sends with its PAR, token and
 * resource requests is extracted and checked (typ, alg, jwk, jti, htm, htu, iat, nbf, exp, ath, the nonce the
 * server supplied, the signature), the DPoP-bound access token is issued and checked at the resource, and the
 * `use_dpop_nonce` error responses carry the server's nonce.
 *
 * upstream: AbstractFAPI2SPFinalClientTest.DPopTokenRequestHelper and the sequence/as/PerformDpopProof*Checks
 * sequences
 */
import { createHash } from "node:crypto";
import { calculateJwkThumbprint } from "jose";
import { condition, soft, type Condition } from "../suite/conditions.ts";
import { isJOSEException, ParseException } from "../suite/errors.ts";
import { verifyJwsSignature, type ParsedJwt } from "../suite/jose.ts";
import { isPrivate, parseJWK } from "../suite/jose-jwk.ts";
import { jwtStringToJsonObjectForEnvironment } from "../suite/jose-jwt.ts";
import { getString } from "../suite/json.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import type { IncomingRequest } from "../suite/server.ts";
import { FAPI2_ALLOWED_ALGS } from "./discovery.ts";
import { toUsAscii } from "./id-token.ts";
import { generateNQChar } from "./registration.ts";

/** The parsed DPoP proof (upstream env "incoming_dpop_proof"; `computed_dpop_jkt` once validated) */
export type DpopProof = ParsedJwt & { computed_dpop_jkt?: string };

/** The DPoP-bound access token (upstream env "dpop_access_token": the token and the jkt it is bound to) */
export interface DpopAccessToken {
	value: string;
	jkt: string;
}

/** The nonces the server supplied (upstream env "authorization_server_dpop_nonce", "resource_server_dpop_nonce") */
export interface DpopNonces {
	authorizationServer: string | null;
	resourceServer: string | null;
}

/** The jti values of the proofs presented so far (upstream: a process-wide cache of 256; here per test) */
export type JtiCache = string[];

const JTI_CACHE_SIZE = 256;

const TIME_SKEW_MILLIS = 5 * 60 * 1000; // 5 minute allowable skew for testing

/** A header read as a string (OIDFJSON.getString): null when absent, an error when repeated */
function header(req: IncomingRequest, name: string): string | null {
	const v = req.headers[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

/** A numeric claim (Environment.getLong): null when absent or JSON null */
function long(claims: Record<string, unknown>, name: string): number | null {
	const v = claims[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "number") {
		throw new Error(`A number is required for incoming_dpop_proof claims.${name} but ${typeof v} was found`);
	}
	return Math.trunc(v);
}

/** Nimbus JWK.computeThumbprint(): the RFC 7638 SHA-256 thumbprint */
async function computeThumbprint(jwk: Record<string, unknown>): Promise<string> {
	return calculateJwkThumbprint(jwk as never, "sha256");
}

// ---------------------------------------------------------------------------------------------------------------
// the proof

/**
 * The DPoP header of the request, parsed (never decrypted: a proof must not be encrypted).
 *
 * upstream: condition/rs/ExtractDpopProofFromHeader.java (condition/AbstractExtractJWT.extractJWT)
 */
export function extractDpopProofFromHeader(req: IncomingRequest, ...requirements: string[]): DpopProof {
	const c: Condition = condition("ExtractDpopProofFromHeader", ...requirements);
	const dpop = header(req, "dpop");
	if (!dpop) {
		c.failure("Couldn't find DPoP Proof header");
	}
	try {
		const proof = jwtStringToJsonObjectForEnvironment(dpop) as unknown as DpopProof;
		// save the parsed token
		c.success("Found and parsed the incoming_dpop_proof from incoming_request", { ...proof });
		return proof;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse incoming_dpop_proof from incoming_request as a JWT", e, {
				incoming_dpop_proof: dpop,
			});
		}
		if (isJOSEException(e)) {
			c.failureFrom("Decrypting incoming_dpop_proof from incoming_request failed", e, { incoming_dpop_proof: dpop });
		}
		throw e;
	}
}

/**
 * The common checks on a proof: typ, a public jwk of a supported kind (its thumbprint is kept as
 * `computed_dpop_jkt`), a FAPI 2 alg, jti, htm and htu of this request, iat present, exp plausible, and ath
 * present only on a resource request.
 *
 * upstream: condition/as/AbstractValidateDpopProof.java (validateDpopProof)
 */
async function validateDpopProof(
	c: Condition,
	proof: DpopProof,
	req: IncomingRequest,
	isResourceRequest: boolean,
): Promise<void> {
	const now = Date.now(); // to check timestamps
	// Check Header claims
	const typ = proof.header["typ"];
	if (typ == null) {
		c.failure("'typ' claim in DPoP Proof header is missing");
	}
	if (getString(typ) !== "dpop+jwt") {
		c.failure("Invalid DPoP Proof 'typ' header", { expected: "dpop+jwt", actual: getString(typ) });
	}
	const jsonJwk = proof.header["jwk"];
	if (jsonJwk == null) {
		c.failure("'jwk' claim in DPoP Proof is missing");
	}
	try {
		const jwk = parseJWK(JSON.stringify(jsonJwk));
		if (isPrivate(jwk)) {
			c.failure("DPoP Proof jwk contains private key information", { jwk: JSON.stringify(jsonJwk) });
		}
		if (jwk["kty"] === "OKP" && jwk["crv"] !== "Ed25519") {
			c.failure("Unsupported curve for OKP key", { JWK: JSON.stringify(jsonJwk), curve: String(jwk["crv"]) });
		}
		// compute and save jkt to avoid parsing JWK again when needed
		proof.computed_dpop_jkt = await computeThumbprint(jwk);
	} catch (e) {
		if (e instanceof ParseException) {
			c.failure("Invalid DPoP Proof jwk", { jwk: JSON.stringify(jsonJwk) });
		}
		if (isJOSEException(e)) {
			c.failureFrom("DPoP JOSEException", e);
		}
		throw e;
	}
	const alg = proof.header["alg"];
	if (alg == null) {
		c.failure("'alg' claim in DPoP Proof header is missing");
	}
	if (!FAPI2_ALLOWED_ALGS.includes(String(alg))) {
		c.failure("Unsupported 'alg' claim in DPoP Proof header ", {
			"expected one of ": JSON.stringify(FAPI2_ALLOWED_ALGS),
			actual: getString(alg),
		});
	}
	// Check payload claims
	const jti = proof.claims["jti"];
	if (jti == null) {
		c.failure("'jti' claim in DPoP Proof is missing");
	}
	if (getString(jti) === "") {
		c.failure("'jti' claim in DPoP Proof is blank");
	}
	// check jti unique across requests in EnsureDpopProofJtiNotUsed
	const htm = proof.claims["htm"];
	if (htm == null) {
		c.failure("'htm' claim in DPoP Proof is missing");
	}
	const expectedMethod = req.method;
	if (expectedMethod !== getString(htm)) {
		c.failure("Unexpected 'htm' in DPoP Proof", { expected: expectedMethod, actual: getString(htm) });
	}
	const expectedUrl = req.request_url;
	const htu = proof.claims["htu"];
	if (htu == null) {
		c.failure("'htu' claim in DPoP Proof is missing");
	}
	let htuStr = getString(htu);
	// look for '?' query and chop off
	let index = htuStr.indexOf("?");
	if (index !== -1) {
		htuStr = htuStr.substring(0, index);
	}
	// look for '#' fragment and chop off
	index = htuStr.indexOf("#");
	if (index !== -1) {
		htuStr = htuStr.substring(0, index);
	}
	if (expectedUrl !== htuStr) {
		// https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
		// Will not perform normalization comparison since Servers SHOULD try URL syntax normalization
		c.failure("Unexpected 'htu' in DPoP Proof", { expected: expectedUrl, actual: getString(htu) });
	}
	const iat = long(proof.claims, "iat");
	if (iat == null) {
		c.failure("'iat' claim in DPoP Proof is missing");
	}
	// Validate iat values in ValidateDpopProofIat
	// nbf - not actually part of spec; but JWT defines known behaviour that really should be followed
	// Validate nbf in ValidateDpopProofNbf
	// exp - not actually part of spec; but JWT defines known behaviour that really should be followed
	const exp = long(proof.claims, "exp");
	if (exp != null) {
		if (now - TIME_SKEW_MILLIS > exp * 1000) {
			c.failure("DPoP Proof has expired", {
				exp: new Date(exp * 1000).toISOString(),
				now: new Date(now).toISOString(),
			});
		}
		if (exp * 1000 > now + 50 * 365 * 24 * 60 * 60 * 1000) {
			c.failure(
				"'exp' is unreasonably far in the future (more than 50 years), this may indicate the value was incorrectly specified in milliseconds instead of seconds",
				{ exp: new Date(exp * 1000).toISOString(), now: new Date(now).toISOString() },
			);
		}
	}
	const ath = proof.claims["ath"];
	if (!isResourceRequest) {
		// DPoP Request, ensure no 'ath' claim
		if (ath != null) {
			c.failure("DPoP Proof request contains 'ath' claim");
		}
	} else if (ath == null) {
		// Resource request, ensure 'ath' is available
		c.failure("'ath' claim in DPoP Proof is missing");
	}
	c.success("DPoP Proof type, alg, jwk, jti, htm, htu, iat, exp, nbf passed validation checks");
}

/** A PAR or token request's proof (no ath). upstream: condition/as/ValidateDpopProofTokenRequest.java */
export function validateDpopProofTokenRequest(
	proof: DpopProof,
	req: IncomingRequest,
	...requirements: string[]
): Promise<void> {
	return validateDpopProof(condition("ValidateDpopProofTokenRequest", ...requirements), proof, req, false);
}

/** A resource request's proof (with ath). upstream: condition/as/ValidateDpopProofResourceRequest.java */
export function validateDpopProofResourceRequest(
	proof: DpopProof,
	req: IncomingRequest,
	...requirements: string[]
): Promise<void> {
	return validateDpopProof(condition("ValidateDpopProofResourceRequest", ...requirements), proof, req, true);
}

/** upstream: condition/as/ValidateDpopProofIat.java */
export function validateDpopProofIat(proof: DpopProof, ...requirements: string[]): void {
	const c: Condition = condition("ValidateDpopProofIat", ...requirements);
	const now = Date.now(); // to check timestamps
	const iat = long(proof.claims, "iat");
	if (iat == null) {
		c.failure("'iat' claim in DPoP Proof is missing");
	}
	if (now + TIME_SKEW_MILLIS < iat * 1000) {
		c.failure("DPoP Proof 'iat' is in the future", {
			"issued-at": new Date(iat * 1000).toISOString(),
			now: new Date(now).toISOString(),
		});
	}
	if (now - TIME_SKEW_MILLIS > iat * 1000) {
		// as per OIDCC, the client can reasonably assume servers send iat values that match the current time:
		// "The iat Claim can be used to reject tokens that were issued too far away from the current time, limiting
		// the amount of time that nonces need to be stored to prevent attacks. The acceptable range is Client specific."
		c.failure("DPoP Proof  'iat' is more than 5 minutes in the past", {
			"issued-at": new Date(iat * 1000).toISOString(),
			now: new Date(now).toISOString(),
		});
	}
	c.success("DPoP Proof iat value passed validation checks");
}

/** upstream: condition/as/ValidateDpopProofNbf.java */
export function validateDpopProofNbf(proof: DpopProof, ...requirements: string[]): void {
	const c: Condition = condition("ValidateDpopProofNbf", ...requirements);
	const now = Date.now(); // to check timestamps
	const nbf = long(proof.claims, "nbf");
	if (nbf != null) {
		if (now + TIME_SKEW_MILLIS < nbf * 1000) {
			c.failure("DPoP Proof has future not-before", {
				"not-before": new Date(nbf * 1000).toISOString(),
				now: new Date(now).toISOString(),
			});
		}
		if (now - TIME_SKEW_MILLIS > nbf * 1000) {
			c.failure("DPoP Proof 'nbf' is more than 5 minutes in the past", {
				"not-before": new Date(nbf * 1000).toISOString(),
				now: new Date(now).toISOString(),
			});
		}
	}
	c.success("DPoP Proof nbf value passed validation checks");
}

/** upstream: condition/client/EnsureDpopProofJtiNotAlreadyUsed.java */
export function ensureDpopProofJtiNotAlreadyUsed(
	proof: DpopProof,
	jtiCache: JtiCache,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureDpopProofJtiNotAlreadyUsed", ...requirements);
	const jti = proof.claims["jti"];
	if (jti == null || getString(jti) === "") {
		c.failure("DPoP Proof jti not found in request");
	}
	const value = getString(jti);
	if (jtiCache.includes(value)) {
		c.failure(
			"Proof jti is the same as one that was already presented to the conformance suite. jti must be unique in every DPoP Proof.",
			{ jti: value },
		);
	}
	if (jtiCache.length >= JTI_CACHE_SIZE) {
		jtiCache.splice(0, 50);
	}
	jtiCache.push(value);
	c.success("Proof jti seems to be unique to this request", { jti: value });
}

/**
 * Whether the proof carries the nonce the server expects; what is wrong with it is logged (never a failure: the
 * endpoint answers with a use_dpop_nonce error instead).
 *
 * upstream: condition/as/AbstractValidateDpopProofNonce.java (isValidDpopNonce)
 */
function isValidDpopNonce(c: Condition, proof: DpopProof, expectedNonce: string | null): boolean {
	let isValid = false;
	// check for incoming nonce
	const incomingNonce = proof.claims["nonce"];
	if (expectedNonce == null) {
		// server did not set nonce
		if (incomingNonce != null) {
			// Spec is unclear whether supplying a nonce when none is requested is an error. Treat this as an error by
			// default
			c.log("DPoP Proof nonce supplied where none is expected");
		} else {
			isValid = true;
			c.success("DPoP nonce not required");
		}
	} else if (incomingNonce == null) {
		// server set nonce
		c.log("DPoP Proof nonce not supplied", { expected: expectedNonce });
	} else if (expectedNonce !== getString(incomingNonce)) {
		c.log("DPoP Proof nonce is invalid", { expected: expectedNonce, actual: incomingNonce });
	} else {
		isValid = true;
	}
	return isValid;
}

/**
 * The nonce check of one endpoint: the expected nonce when the proof's nonce is missing or wrong (upstream
 * "<endpoint>_endpoint_dpop_nonce_error": what the error response then supplies), null when fine or no nonce is
 * required.
 */
function validateEndpointDpopProofNonce(
	name: string,
	label: string,
	proof: DpopProof,
	expectedNonce: string | null,
	requirements: string[],
): string | null {
	const c: Condition = condition(name, ...requirements);
	if (isValidDpopNonce(c, proof, expectedNonce)) {
		c.success(`${label} endpoint DPoP nonce matches expected value`, { expected: expectedNonce });
		return null;
	}
	if (expectedNonce != null) {
		// saves expected nonce to be used by Create<endpoint>DpopErrorResponse to return DPoP nonce error
		c.log(`${label} endpoint DPoP nonce is invalid`, { expected: expectedNonce });
		return expectedNonce;
	}
	return null;
}

/** upstream: condition/as/ValidateParEndpointDpopProofNonce.java */
export function validateParEndpointDpopProofNonce(
	proof: DpopProof,
	expectedNonce: string | null,
	...requirements: string[]
): string | null {
	return validateEndpointDpopProofNonce("ValidateParEndpointDpopProofNonce", "PAR", proof, expectedNonce, requirements);
}

/** upstream: condition/as/ValidateTokenEndpointDpopProofNonce.java */
export function validateTokenEndpointDpopProofNonce(
	proof: DpopProof,
	expectedNonce: string | null,
	...requirements: string[]
): string | null {
	return validateEndpointDpopProofNonce(
		"ValidateTokenEndpointDpopProofNonce",
		"Token",
		proof,
		expectedNonce,
		requirements,
	);
}

/** upstream: condition/as/ValidateResourceEndpointDpopProofNonce.java */
export function validateResourceEndpointDpopProofNonce(
	proof: DpopProof,
	expectedNonce: string | null,
	...requirements: string[]
): string | null {
	return validateEndpointDpopProofNonce(
		"ValidateResourceEndpointDpopProofNonce",
		"Resource",
		proof,
		expectedNonce,
		requirements,
	);
}

/**
 * The proof's signature verifies with the key in its header.
 *
 * upstream: condition/as/ValidateDpopProofSignature.java (AbstractVerifyJwsSignature)
 */
export async function validateDpopProofSignature(proof: DpopProof, ...requirements: string[]): Promise<void> {
	const c: Condition = condition("ValidateDpopProofSignature", ...requirements);
	const jwkJson = proof.header["jwk"];
	let jwkSet: { keys: unknown[] };
	try {
		jwkSet = { keys: [parseJWK(JSON.stringify(jwkJson))] };
	} catch (e) {
		if (e instanceof ParseException) {
			c.failure("Invalid DPoP Proof jwk", { jwk: JSON.stringify(jwkJson) });
		}
		throw e;
	}
	await verifyJwsSignature(c, proof.value, jwkSet, "DPoP Proof", false, "dpop proof header");
}

/**
 * The key the authorization code was bound to at the PAR endpoint (`expected`, upstream
 * "authorization_code_dpop_jkt"; empty when the request was not bound) is the proof's key.
 *
 * upstream: condition/as/ValidateAuthorizationCodeDpopBindingKey.java
 */
export function validateAuthorizationCodeDpopBindingKey(
	proof: DpopProof,
	expected: string | null,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateAuthorizationCodeDpopBindingKey", ...requirements);
	const actual = proof.computed_dpop_jkt ?? null;
	if (!expected) {
		c.success("Authorization request does not use DPoP authorization code binding", { dpop_jkt: actual });
		return;
	}
	if (expected === actual) {
		c.success("Authorization code DPoP binding matches dpop_jkt", { dpop_jkt: actual });
		return;
	}
	c.failure("Mismatched authorization code DPoP binding", { expected, actual });
}

/**
 * The key the authorization code is bound to: the dpop_jkt of the PAR request (in the request object or the form)
 * must match the proof's key; without a proof the dpop_jkt is taken, without either the code is not bound ("").
 *
 * upstream: condition/as/ExtractParAuthorizationCodeDpopBindingKey.java
 */
export function extractParAuthorizationCodeDpopBindingKey(
	requestObject: ParsedJwt | null,
	parParams: Record<string, unknown>,
	proof: DpopProof | null,
	...requirements: string[]
): string {
	const c: Condition = condition("ExtractParAuthorizationCodeDpopBindingKey", ...requirements);
	// Look in request object
	let dpopJkt = typeof requestObject?.claims["dpop_jkt"] === "string" ? requestObject.claims["dpop_jkt"] : null;
	if (!dpopJkt) {
		// Look in PAR unsigned request
		dpopJkt = typeof parParams["dpop_jkt"] === "string" ? parParams["dpop_jkt"] : null;
	}
	// client may not have sent DPoP proof
	const computedDpopJkt = proof?.computed_dpop_jkt ?? null;
	if (dpopJkt && computedDpopJkt) {
		if (dpopJkt !== computedDpopJkt) {
			c.failure("dpop_jkt in request doesn't match DPoP proof JWK thumbprint.", {
				dpop_jkt: dpopJkt,
				"DPoP thumbprint": computedDpopJkt,
			});
		}
		c.success("dpop_jkt matches computed JWK thumbprint", { dpop_jkt: dpopJkt });
		return computedDpopJkt;
	}
	if (computedDpopJkt) {
		c.success("Using computed_dpop_jkt as dpop_jkt", { authorization_code_dpop_jkt: computedDpopJkt });
		return computedDpopJkt;
	}
	if (dpopJkt) {
		c.success("Using dpop_jkt in request", { dpop_jkt: dpopJkt });
		return dpopJkt;
	}
	c.success("Request does not use DPoP Authorization code binding");
	return "";
}

// ---------------------------------------------------------------------------------------------------------------
// the sequences

/**
 * The checks on the proof of a PAR request. Returns the nonce error (the nonce the error response must supply) or
 * null.
 *
 * upstream: sequence/as/PerformDpopProofParRequestChecks.java with condition/as/ValidateDpopProofTokenRequest.java,
 * ValidateDpopProofIat.java, ValidateDpopProofNbf.java, condition/client/EnsureDpopProofJtiNotAlreadyUsed.java,
 * condition/as/ValidateParEndpointDpopProofNonce.java, ValidateDpopProofSignature.java
 */
export async function performDpopProofParRequestChecks(
	proof: DpopProof,
	req: IncomingRequest,
	nonces: DpopNonces,
	jtiCache: JtiCache,
): Promise<string | null> {
	await soft(() => validateDpopProofTokenRequest(proof, req, "DPOP-4.3"));
	soft(() => validateDpopProofIat(proof, "DPOP-11.1", "FAPI2-SP-ID2-5.3.2.1-14"));
	soft(() => validateDpopProofNbf(proof, "FAPI2-SP-ID2-5.3.2.1-14"));
	soft(() => ensureDpopProofJtiNotAlreadyUsed(proof, jtiCache, "DPOP-4.2", "DPOP-11"));
	const nonceError =
		soft(() => validateParEndpointDpopProofNonce(proof, nonces.authorizationServer), "warning") ?? null;
	await soft(() => validateDpopProofSignature(proof, "DPOP-4.3-6"));
	return nonceError;
}

/**
 * The checks on the proof of a token request, with the authorization code's binding (`authorizationCodeDpopJkt`).
 *
 * upstream: sequence/as/PerformDpopProofTokenRequestChecks.java with condition/as/ValidateDpopProofTokenRequest.java,
 * ValidateDpopProofIat.java, ValidateDpopProofNbf.java, condition/client/EnsureDpopProofJtiNotAlreadyUsed.java,
 * condition/as/ValidateTokenEndpointDpopProofNonce.java, ValidateDpopProofSignature.java,
 * ValidateAuthorizationCodeDpopBindingKey.java
 */
export async function performDpopProofTokenRequestChecks(
	proof: DpopProof,
	req: IncomingRequest,
	nonces: DpopNonces,
	jtiCache: JtiCache,
	authorizationCodeDpopJkt: string | null,
): Promise<string | null> {
	await soft(() => validateDpopProofTokenRequest(proof, req, "DPOP-4.3"));
	soft(() => validateDpopProofIat(proof, "DPOP-11.1", "FAPI2-SP-ID2-5.3.2.1-14"));
	soft(() => validateDpopProofNbf(proof, "FAPI2-SP-ID2-5.3.2.1-14"));
	soft(() => ensureDpopProofJtiNotAlreadyUsed(proof, jtiCache, "DPOP-4.2", "DPOP-11"));
	const nonceError =
		soft(() => validateTokenEndpointDpopProofNonce(proof, nonces.authorizationServer), "warning") ?? null;
	await soft(() => validateDpopProofSignature(proof, "DPOP-4.3-6"));
	soft(() => validateAuthorizationCodeDpopBindingKey(proof, authorizationCodeDpopJkt, "DPOP-10"));
	return nonceError;
}

/**
 * The checks on the proof of a resource request.
 *
 * upstream: sequence/as/PerformDpopProofResourceRequestChecks.java with
 * condition/as/ValidateDpopProofResourceRequest.java, ValidateDpopProofIat.java, ValidateDpopProofNbf.java,
 * condition/client/EnsureDpopProofJtiNotAlreadyUsed.java, condition/as/ValidateResourceEndpointDpopProofNonce.java,
 * ValidateDpopProofSignature.java
 */
export async function performDpopProofResourceRequestChecks(
	proof: DpopProof,
	req: IncomingRequest,
	nonces: DpopNonces,
	jtiCache: JtiCache,
): Promise<string | null> {
	await soft(() => validateDpopProofResourceRequest(proof, req, "DPOP-4.3"));
	soft(() => validateDpopProofIat(proof, "DPOP-11.1", "FAPI2-SP-ID2-5.3.2.1-14"));
	soft(() => validateDpopProofNbf(proof, "FAPI2-SP-ID2-5.3.2.1-14"));
	soft(() => ensureDpopProofJtiNotAlreadyUsed(proof, jtiCache, "DPOP-4.2", "DPOP-11"));
	const nonceError =
		soft(() => validateResourceEndpointDpopProofNonce(proof, nonces.resourceServer), "warning") ?? null;
	await soft(() => validateDpopProofSignature(proof, "DPOP-4.3-6"));
	return nonceError;
}

// ---------------------------------------------------------------------------------------------------------------
// the access token

/**
 * A DPoP-bound access token: a random token bound to the thumbprint of the proof's key (token_type DPoP).
 *
 * upstream: condition/as/GenerateDpopAccessToken.java
 */
export async function generateDpopAccessToken(proof: DpopProof): Promise<DpopAccessToken> {
	const c: Condition = condition("GenerateDpopAccessToken");
	const jsonJwk = proof.header["jwk"];
	if (jsonJwk == null) {
		c.failure("'jwk' claim in DPoP Proof is missing");
	}
	try {
		const jwk = parseJWK(JSON.stringify(jsonJwk));
		const computedJkt = await computeThumbprint(jwk);
		const token: DpopAccessToken = { value: randomAlphanumeric(50), jkt: computedJkt };
		c.success("Generated DPoP access token and jkt for DPoP Proof JWK", { dpop_access_token: token });
		return token;
	} catch (e) {
		if (e instanceof ParseException || isJOSEException(e)) {
			c.failure("Invalid DPoP Proof JWK", { jwk: JSON.stringify(jsonJwk) });
		}
		throw e;
	}
}

/** The access token of the Authorization: DPoP header. upstream: condition/rs/ExtractDpopAccessTokenFromHeader.java */
export function extractDpopAccessTokenFromHeader(req: IncomingRequest, ...requirements: string[]): string {
	const c: Condition = condition("ExtractDpopAccessTokenFromHeader", ...requirements);
	const authHeader = header(req, "authorization");
	if (authHeader && authHeader.toLowerCase().startsWith("dpop ")) {
		const tokenFromHeader = authHeader.substring("dpop ".length);
		if (tokenFromHeader) {
			c.success("Found DPoP access token", { "DPoP token": tokenFromHeader });
			return tokenFromHeader;
		}
	}
	c.failure("Couldn't find DPoP access token", { Header: authHeader });
}

/** upstream: condition/as/ValidateDpopAccessToken.java */
export function validateDpopAccessToken(
	incomingDpopToken: string,
	dpopAccessToken: DpopAccessToken | null,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateDpopAccessToken", ...requirements);
	if (dpopAccessToken == null) {
		// UPSTREAM: @PreEnvironment(required = "dpop_access_token"): the framework stops the test before the condition
		throw new Error("ValidateDpopAccessToken: no DPoP access token was issued in this test");
	}
	if (dpopAccessToken.value === incomingDpopToken) {
		c.success("DPoP Access Token is valid", { "DPoP Access Token": dpopAccessToken.value });
		return;
	}
	c.failure("Invalid DPoP Access Token", { expected: dpopAccessToken.value, actual: incomingDpopToken });
}

/** The access token is bound to the proof's key. upstream: condition/as/ValidateDpopAccessTokenJkt.java */
export async function validateDpopAccessTokenJkt(
	proof: DpopProof,
	dpopAccessToken: DpopAccessToken,
	...requirements: string[]
): Promise<void> {
	const c: Condition = condition("ValidateDpopAccessTokenJkt", ...requirements);
	// Compare the stored jkt thumbprint with the DPoP Proof JWK
	const jsonJwk = proof.header["jwk"];
	if (jsonJwk == null) {
		c.failure("'jwk' claim in DPoP Proof is missing");
	}
	try {
		const jwk = parseJWK(JSON.stringify(jsonJwk));
		const { value, jkt } = dpopAccessToken;
		if (!jkt) {
			c.failure("DPoP Access Token jkt binding is not available", { "DPoP Access Token": dpopAccessToken });
		}
		const computedJkt = await computeThumbprint(jwk);
		if (computedJkt !== jkt) {
			c.failure("DPoP Access Token jkt does not match JWK thumbprint", { expected: jkt, actual: computedJkt });
		}
		c.success("DPoP Access Token is constrained to DPoP Proof JWK", { "DPoP Access Token": value });
	} catch (e) {
		if (e instanceof ParseException || isJOSEException(e)) {
			c.failure("Invalid DPoP Proof jwk", { jwk: JSON.stringify(jsonJwk) });
		}
		throw e;
	}
}

/** The proof's ath is the hash of the access token presented. upstream: condition/as/ValidateDpopProofAccessTokenHash.java */
export function validateDpopProofAccessTokenHash(
	proof: DpopProof,
	incomingDpopToken: string,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateDpopProofAccessTokenHash", ...requirements);
	const ath = typeof proof.claims["ath"] === "string" ? proof.claims["ath"] : null;
	if (!incomingDpopToken) {
		c.failure("DPoP Access Token is not available.");
	}
	if (!ath) {
		c.failure("DPoP Proof 'ath' claim is not available.");
	}
	const expectedAth = createHash("sha256")
		.update(Buffer.from(toUsAscii(incomingDpopToken), "latin1"))
		.digest()
		.toString("base64url");
	if (ath !== expectedAth) {
		c.failure("Mismatch between DPoP Proof ath and access token", {
			incoming_dpop_access_token: incomingDpopToken,
			expected: expectedAth,
			actual: ath,
		});
	}
	c.success("DPoP Proof ath claim matches DPoP access token hash", { ath });
}

/**
 * The access token of a resource request is the DPoP-bound one issued, bound to the proof's key, and hashed in the
 * proof.
 *
 * upstream: condition/rs/RequireDpopAccessToken.java with condition/as/ValidateDpopAccessToken.java,
 * ValidateDpopAccessTokenJkt.java, ValidateDpopProofAccessTokenHash.java
 */
export async function requireDpopAccessToken(
	proof: DpopProof,
	incomingDpopToken: string,
	dpopAccessToken: DpopAccessToken | null,
): Promise<void> {
	validateDpopAccessToken(incomingDpopToken, dpopAccessToken, "DPOP-4.3");
	await validateDpopAccessTokenJkt(proof, dpopAccessToken as DpopAccessToken, "DPOP-4.3-12");
	// UPSTREAM: the requirement tag's typos are upstream's
	validateDpopProofAccessTokenHash(proof, incomingDpopToken, "DP0P-4.3.-12");
}

// ---------------------------------------------------------------------------------------------------------------
// the nonces and the use_dpop_nonce responses

/** upstream: condition/as/CreateAuthorizationServerDpopNonce.java */
export function createAuthorizationServerDpopNonce(): string {
	// DPOP spec does not define max length for nonce value
	const nonce = generateNQChar(50, 10, 30);
	condition("CreateAuthorizationServerDpopNonce").success("Created Authorization Server DPoP nonce", {
		authorization_server_dpop_nonce: nonce,
	});
	return nonce;
}

/** upstream: condition/rs/CreateResourceServerDpopNonce.java */
export function createResourceServerDpopNonce(): string {
	const nonce = generateNQChar(50, 10, 30);
	condition("CreateResourceServerDpopNonce").success("Created Resource Server nonce", {
		resource_server_dpop_nonce: nonce,
	});
	return nonce;
}

/** A use_dpop_nonce error response (status, headers and, at the authorization server, the JSON body) */
export interface DpopErrorResponse {
	status: number;
	headers: Record<string, string>;
	body: Record<string, string> | null;
}

/**
 * The 400 use_dpop_nonce response of an authorization server endpoint, with the nonce to use in DPoP-Nonce.
 * UPSTREAM: the condition logs nothing itself, so the framework logs "Condition ran but did not log anything".
 *
 * upstream: condition/as/AbstractCreateDpopErrorResponse.java (createAuthorizationServerEndpointDpopErrorResponse)
 */
function createAuthorizationServerEndpointDpopErrorResponse(name: string, expectedNonce: string): DpopErrorResponse {
	condition(name).log("Condition ran but did not log anything");
	return {
		status: 400,
		headers: { "DPoP-Nonce": expectedNonce },
		body: { error: "use_dpop_nonce", error_description: "Authorization server requires nonce in DPoP proof" },
	};
}

/** upstream: condition/as/CreatePAREndpointDpopErrorResponse.java */
export function createPAREndpointDpopErrorResponse(expectedNonce: string): DpopErrorResponse {
	return createAuthorizationServerEndpointDpopErrorResponse("CreatePAREndpointDpopErrorResponse", expectedNonce);
}

/** upstream: condition/as/CreateTokenEndpointDpopErrorResponse.java */
export function createTokenEndpointDpopErrorResponse(expectedNonce: string): DpopErrorResponse {
	return createAuthorizationServerEndpointDpopErrorResponse("CreateTokenEndpointDpopErrorResponse", expectedNonce);
}

/**
 * The 401 use_dpop_nonce challenge of a resource server endpoint (`authScheme` names the scheme of the
 * WWW-Authenticate header). UPSTREAM: the condition logs nothing itself.
 *
 * upstream: condition/as/AbstractCreateDpopErrorResponse.java (createResourceServerEndpointDpopErrorResponse)
 */
function createResourceServerEndpointDpopErrorResponse(
	name: string,
	authScheme: string,
	expectedNonce: string,
): DpopErrorResponse {
	condition(name).log("Condition ran but did not log anything");
	return {
		status: 401,
		headers: {
			"WWW-Authenticate": `${authScheme} error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"`,
			"DPoP-Nonce": expectedNonce,
		},
		body: null,
	};
}

/** upstream: condition/rs/CreateResourceEndpointDpopErrorResponse.java */
export function createResourceEndpointDpopErrorResponse(expectedNonce: string): DpopErrorResponse {
	return createResourceServerEndpointDpopErrorResponse(
		"CreateResourceEndpointDpopErrorResponse",
		"DPoP",
		expectedNonce,
	);
}

/** The challenge with the scheme in another case ("dPoP"). upstream: condition/rs/CreateResourceEndpointDpopErrorAltSchemeCaseResponse.java */
export function createResourceEndpointDpopErrorAltSchemeCaseResponse(expectedNonce: string): DpopErrorResponse {
	return createResourceServerEndpointDpopErrorResponse(
		"CreateResourceEndpointDpopErrorAltSchemeCaseResponse",
		"dPoP",
		expectedNonce,
	);
}

/**
 * The id_token checks: the standard ones upstream runs on every id_token (PerformStandardIdTokenChecks) and the
 * ones individual test modules add (kid, alg, at_hash / c_hash, claims that were not requested).
 *
 *   await idToken.performStandardIdTokenChecks(op, client, request, tokens.idToken);
 */
import { createHash } from "node:crypto";
import { condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import { ParseException, verifyJwsSignature, type ParsedJwt } from "../suite/jose.ts";
import { getDigestAlgorithmForSigAlg, InvalidAlgorithmException } from "../suite/jose-algorithms.ts";
import { parseSignedJWT } from "../suite/jose-jwt.ts";
import { isSymmetricJWEAlgorithm } from "../suite/jose-jwe.ts";
import type { AuthorizationRequest } from "./authorization.ts";
import type { Op } from "./op.ts";
import type { Client } from "./registration.ts";
import type { AccessToken } from "./token.ts";

const DAY_MILLIS = 24 * 60 * 60 * 1000;
/** 5 minute allowable clock skew */
const TIME_SKEW_MILLIS = 5 * 60 * 1000;

function claim(idToken: ParsedJwt, name: string): unknown {
	return idToken.claims[name];
}

function stringClaim(idToken: ParsedJwt, name: string): string | null {
	const v = claim(idToken, name);
	return typeof v === "string" ? v : null;
}

function longClaim(idToken: ParsedJwt, name: string): number | null {
	const v = claim(idToken, name);
	return typeof v === "number" ? Math.trunc(v) : null;
}

/**
 * iss, aud, exp, iat, auth_time, acr and nbf (OIDCC 3.1.3.7).
 *
 * upstream: condition/client/ValidateIdToken.java
 */
export function validateIdToken(
	idToken: ParsedJwt,
	op: Pick<Op, "metadata">,
	client: Pick<Client, "client_id">,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateIdToken", ...requirements);
	const clientId = client.client_id;
	const issuer = op.metadata.issuer;
	const now = Date.now();
	if (!clientId || !issuer) {
		c.failure("Couldn't find values to test ID token against");
	}
	if (claim(idToken, "iss") == null) {
		c.failure("'iss' claim missing");
	}
	if (issuer !== stringClaim(idToken, "iss")) {
		c.failure("Issuer mismatch", { expected: issuer, actual: stringClaim(idToken, "iss") });
	}
	const aud = claim(idToken, "aud");
	if (aud == null) {
		c.failure("'aud' claim missing");
	}
	if (Array.isArray(aud)) {
		if (!aud.includes(clientId)) {
			c.failure("'aud' array does not contain our client id", { expected: clientId, actual: aud });
		}
	} else if (clientId !== String(aud)) {
		c.failure("'aud' is not our client id", { expected: clientId, actual: aud });
	}
	const exp = longClaim(idToken, "exp");
	if (exp == null) {
		c.failure("'exp' claim missing");
	}
	if (now - TIME_SKEW_MILLIS > exp * 1000) {
		c.failure("Token expired", { expiration: new Date(exp * 1000), now: new Date(now) });
	}
	if (exp * 1000 > now + 50 * 365 * DAY_MILLIS) {
		c.failure(
			"'exp' is unreasonably far in the future (more than 50 years), this may indicate the value was incorrectly specified in milliseconds instead of seconds",
			{ exp: new Date(exp * 1000), now: new Date(now) },
		);
	}
	const iat = longClaim(idToken, "iat");
	if (iat == null) {
		c.failure("'iat' claim missing");
	}
	if (now + TIME_SKEW_MILLIS < iat * 1000) {
		c.failure("Token 'iat' in the future", { "issued-at": new Date(iat * 1000), now: new Date(now) });
	}
	if (now - TIME_SKEW_MILLIS > iat * 1000) {
		// the client can reasonably assume servers send iat values that match the current time (OIDCC 3.1.3.7)
		c.failure("Token 'iat' more than 5 minutes in the past", { "issued-at": new Date(iat * 1000), now: new Date(now) });
	}
	const authTime = longClaim(idToken, "auth_time");
	if (authTime != null) {
		if (now - 365 * DAY_MILLIS > authTime * 1000) {
			c.failure("id_token auth_time is over a year in the past", {
				auth_time: new Date(authTime * 1000),
				now: new Date(now),
			});
		}
		if (now + TIME_SKEW_MILLIS < authTime * 1000) {
			c.failure("id_token auth_time is in the future", { auth_time: new Date(authTime * 1000), now: new Date(now) });
		}
	}
	if (stringClaim(idToken, "acr") === "") {
		c.failure("id_token acr is an empty string");
	}
	const nbf = longClaim(idToken, "nbf");
	if (nbf != null && now + TIME_SKEW_MILLIS < nbf * 1000) {
		// not part of OIDC; JWT defines it. Only logged, it does not make the token invalid
		c.log("Token has future not-before", { "not-before": new Date(nbf * 1000), now: new Date(now) });
	}
	c.success("ID token iss, aud, exp, iat, auth_time, acr & nbf claims passed validation checks");
}

export interface ElementValidator {
	description: string;
	isValid(v: unknown): boolean;
}

/** Java String.isBlank */
function isBlank(s: string): boolean {
	// oxlint-disable-next-line no-control-regex -- Character.isWhitespace includes the separators U+001C-U+001F
	return /^[\s\u001c-\u001f]*$/.test(s);
}

export const VALIDATE_STRING: ElementValidator = {
	description: "a string with content",
	// a claim that is not returned SHOULD be omitted, not null or empty; "null" has been seen as a user's name
	isValid: (v) => typeof v === "string" && !isBlank(v) && v.toLowerCase() !== "null",
};

function isSaneBirthYear(year: number): boolean {
	return year >= 1850 && year <= new Date().getFullYear();
}

export const VALIDATE_BIRTHDATE: ElementValidator = {
	description: "a valid birthdate in the format stated in OpenID Connect Standard - YYYY-MM-DD, 0000-MM-DD or YYYY",
	isValid(v) {
		if (!VALIDATE_STRING.isValid(v)) {
			return false;
		}
		const date = v as string;
		const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
		if (m) {
			const [year, month, day] = [Number(m[1]), Number(m[2]), Number(m[3])];
			const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
			const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
			if (month < 1 || month > 12 || day < 1 || day > days) {
				return false;
			}
			// the year can be 0000 when it is not held or not released
			return year === 0 || isSaneBirthYear(year);
		}
		return /^[+-]?\d+$/.test(date) && isSaneBirthYear(Number.parseInt(date, 10));
	},
};

export const VALIDATE_BOOLEAN: ElementValidator = { description: "a boolean", isValid: (v) => typeof v === "boolean" };
export const VALIDATE_NUMBER: ElementValidator = { description: "a number", isValid: (v) => typeof v === "number" };
export const VALIDATE_JSON_OBJECT: ElementValidator = {
	description: "a JSON object",
	isValid: (v) => typeof v === "object" && v !== null && !Array.isArray(v),
};

/**
 * Validates an object of standard claims, logging each claim (upstream AbstractValidateOpenIdStandardClaims
 * ObjectValidator); unknown claims are collected in `unknown`.
 */
export function objectValidator(
	c: Condition,
	context: string | null,
	claims: Map<string, ElementValidator>,
	unknown: Record<string, unknown>,
): ElementValidator {
	return {
		description: "a valid object or contains invalid claims",
		isValid(elt) {
			if (typeof elt !== "object" || elt === null || Array.isArray(elt) || Object.keys(elt).length === 0) {
				c.logFailure("Not a JSON object or no identity claims");
				return false;
			}
			let ok = true;
			for (const [key, value] of Object.entries(elt)) {
				const name = context != null ? context + "." + key : key;
				const validator = claims.get(key);
				if (validator == null) {
					c.log("Skipping unknown claim: " + name);
					unknown[name] = value;
					continue;
				}
				if (validator.isValid(value)) {
					c.log(name + " is " + validator.description);
				} else {
					c.logFailure(name + " is not " + validator.description);
					ok = false;
				}
			}
			return ok;
		},
	};
}

/** Claims specific to the id_token; what is left are the identity claims of OIDCC 5.1 */
const ID_TOKEN_NON_IDENTITY_CLAIMS = [
	"iss",
	"aud",
	"exp",
	"iat",
	"auth_time",
	"nonce",
	"acr",
	"amr",
	"azp",
	"c_hash",
	"at_hash",
	"s_hash",
	"jti",
	"nbf",
	"verified_claims",
];

/**
 * The identity claims in the id_token have the types OIDCC 5.1 defines. Returns the unknown claims.
 *
 * upstream: condition/client/ValidateIdTokenStandardClaims.java (AbstractValidateOpenIdStandardClaims)
 */
export function validateIdTokenStandardClaims(idToken: ParsedJwt, ...requirements: string[]): Record<string, unknown> {
	const c: Condition = condition("ValidateIdTokenStandardClaims", ...requirements);
	const identityClaims = structuredClone(idToken.claims);
	for (const name of ID_TOKEN_NON_IDENTITY_CLAIMS) {
		delete identityClaims[name];
	}
	const unknown: Record<string, unknown> = {};
	const address = new Map(
		["formatted", "street_address", "locality", "region", "postal_code", "country"].map((k) => [k, VALIDATE_STRING]),
	);
	const standard = new Map<string, ElementValidator>([
		...[
			"sub",
			"name",
			"given_name",
			"family_name",
			"middle_name",
			"nickname",
			"preferred_username",
			"profile",
			"picture",
			"website",
			"email",
		].map((k): [string, ElementValidator] => [k, VALIDATE_STRING]),
		["email_verified", VALIDATE_BOOLEAN],
		["gender", VALIDATE_STRING],
		["birthdate", VALIDATE_BIRTHDATE],
		["zoneinfo", VALIDATE_STRING],
		["locale", VALIDATE_STRING],
		["phone_number", VALIDATE_STRING],
		["phone_number_verified", VALIDATE_BOOLEAN],
		["address", objectValidator(c, "address", address, unknown)],
		["updated_at", VALIDATE_NUMBER],
		["_claim_names", VALIDATE_JSON_OBJECT],
		["_claim_sources", VALIDATE_JSON_OBJECT],
		// digitalid-financial-api-04.md
		["txn", VALIDATE_STRING],
	]);
	if (!objectValidator(c, null, standard, unknown).isValid(identityClaims)) {
		c.failure("id_token claims are not valid", identityClaims);
	}
	c.success("id_token claims are valid");
	return unknown;
}

/** upstream: condition/client/ValidateIdTokenNonce.java */
export function validateIdTokenNonce(
	idToken: ParsedJwt,
	expectedNonce: string | null,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateIdTokenNonce", ...requirements);
	const nonce = stringClaim(idToken, "nonce");
	if (nonce == null && expectedNonce == null) {
		c.success("nonce is not in id_token, as expected.");
		return;
	}
	if (expectedNonce !== nonce) {
		c.failure("Nonce values mismatch", { actual: nonce, expected: expectedNonce });
	}
	c.success("Nonce values match", { nonce });
}

/** upstream: condition/client/ValidateIdTokenACRClaimAgainstRequest.java */
export function validateIdTokenACRClaimAgainstRequest(
	idToken: ParsedJwt,
	request: Pick<AuthorizationRequest, "params">,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateIdTokenACRClaimAgainstRequest", ...requirements);
	const acr = claim(idToken, "acr");
	if (acr != null && typeof acr !== "string") {
		c.failure("acr value in id_token must be a string", { id_token: idToken });
	}
	const requested = (
		request.params["claims"] as { id_token?: { acr?: { value?: unknown; values?: unknown[] } } } | undefined
	)?.id_token?.acr;
	const values: string[] =
		requested?.values != null
			? requested.values.map(String)
			: requested?.value != null
				? [String(requested.value)]
				: [];
	if (values.length === 0 && requested?.values == null) {
		c.success("Nothing to check; the conformance suite did not request an acr claim in request object");
		return;
	}
	if (acr == null) {
		c.failure(
			"One or more acr values were requested as an 'essential: true' claim so, as the authentication succeeded, the acr used MUST be returned in the id_token",
			{ id_token: idToken, expected: values },
		);
	}
	if (!values.includes(acr)) {
		c.failure("acr value in id_token is not (one of the) requested values", { requested: values, actual: acr });
	}
	c.success("acr value in id_token is (one of) the requested values", { requested: values, actual: acr });
}

/** upstream: condition/client/ValidateIdTokenSignature.java (AbstractVerifyJwsSignature) */
export async function validateIdTokenSignature(
	idToken: ParsedJwt,
	serverJwks: unknown,
	...requirements: string[]
): Promise<void> {
	const c: Condition = condition("ValidateIdTokenSignature", ...requirements);
	await verifyJwsSignature(c, idToken.value, serverJwks, "id_token", false, "server");
}

/** upstream: condition/client/CheckForSubjectInIdToken.java */
export function checkForSubjectInIdToken(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("CheckForSubjectInIdToken", ...requirements);
	const sub = stringClaim(idToken, "sub");
	if (!sub) {
		c.failure("id_token does not contain 'sub'");
	}
	// "It MUST NOT exceed 255 ASCII characters in length." (OIDCC 2)
	if (sub.length > 255) {
		c.failure("id_token 'sub' exceeds 255 ASCII characters", { sub });
	}
	for (let i = 0; i < sub.length; i++) {
		const ch = sub.charCodeAt(i);
		if (ch < 0x20) {
			c.failure(
				`id_token 'sub' contains non-printable character 0x${ch.toString(16).padStart(2, "0")} at offset ${i}`,
				{ sub },
			);
		}
		if (ch >= 0x7f) {
			c.failure(`id_token 'sub' contains non-ASCII character 0x${ch.toString(16).padStart(2, "0")} at offset ${i}`, {
				sub,
			});
		}
	}
	c.success("Found 'sub' in id_token", { sub });
}

/**
 * upstream: condition/client/EnsureIdTokenUpdatedAtValid.java (AbstractUpdatedAtValid)
 *
 * UPSTREAM: reads `updated_at` from the top level of the parsed id_token object (value/header/claims), not from its
 * claims, so it always logs that there is none; kept as is for identical results.
 */
export function ensureIdTokenUpdatedAtValid(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("EnsureIdTokenUpdatedAtValid", ...requirements);
	const updatedAt = (idToken as unknown as Record<string, unknown>)["updated_at"];
	if (typeof updatedAt !== "number") {
		c.log("id_token response does not contain 'updated_at'");
		return;
	}
	const now = Date.now();
	const fields = { updated_at: new Date(updatedAt * 1000), now: new Date(now) };
	if (now + TIME_SKEW_MILLIS < updatedAt * 1000) {
		c.failure("updated_at in id_token appears to be in the future", fields);
	}
	if (Date.UTC(1990, 0, 1) > updatedAt * 1000) {
		c.failure("updated_at in id_token appears to be prior to the year 1990", fields);
	}
	c.success("'updated_at' in id_token response seems to be a valid time", fields);
}

/** upstream: condition/client/ValidateEncryptedIdTokenHasKid.java */
export function validateEncryptedIdTokenHasKid(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("ValidateEncryptedIdTokenHasKid", ...requirements);
	const alg = idToken.jwe_header?.["alg"];
	const kid = idToken.jwe_header?.["kid"];
	if (isSymmetricJWEAlgorithm(alg as string)) {
		c.success("skipping KID check for symmetric alg " + String(alg));
		return;
	}
	if (!kid) {
		c.failure("kid was not found in the encrypted ID token header");
	}
	c.success("kid was found in the encrypted ID token header", { kid });
}

/**
 * The checks that hold for every id_token, in upstream's order (all continue on failure).
 *
 * upstream: sequence/client/PerformStandardIdTokenChecks.java
 */
export async function performStandardIdTokenChecks(
	op: Pick<Op, "metadata" | "jwks">,
	client: Pick<Client, "client_id">,
	request: Pick<AuthorizationRequest, "params" | "nonce">,
	idToken: ParsedJwt,
): Promise<void> {
	soft(() => validateIdToken(idToken, op, client, "OIDCC-3.1.3.7"));
	soft(() => validateIdTokenStandardClaims(idToken, "OIDCC-5.1"));
	soft(() => validateIdTokenNonce(idToken, request.nonce, "OIDCC-2"));
	soft(() => validateIdTokenACRClaimAgainstRequest(idToken, request, "OIDCC-5.5.1.1"));
	await soft(() => validateIdTokenSignature(idToken, op.jwks));
	soft(() => checkForSubjectInIdToken(idToken, "OIDCC-2"));
	soft(() => ensureIdTokenUpdatedAtValid(idToken, "OIDCC-5.1"));
	if (idToken.jwe_header == null) {
		skipped("ValidateEncryptedIdTokenHasKid", { element: ["id_token", "jwe_header"] }, "OIDCC-10.2", "OIDCC-10.2.1");
	} else {
		soft(() => validateEncryptedIdTokenHasKid(idToken, "OIDCC-10.2", "OIDCC-10.2.1"));
	}
}

/** A hash claim of the id_token and the id_token's alg (upstream env "at_hash" / "c_hash") */
export interface ExtractedHash {
	hash: string;
	alg: string;
}

/** upstream: condition/client/ExtractHash.java */
function extractHash(name: string, hashName: string, idToken: ParsedJwt, requirements: string[]): ExtractedHash {
	const c: Condition = condition(name, ...requirements);
	const value = claim(idToken, hashName);
	if (value != null && typeof value !== "string") {
		c.failure(hashName + " in ID token is not a string");
	}
	if (value == null) {
		c.failure("Couldn't find " + hashName + " in ID token");
	}
	const alg = idToken.header["alg"];
	if (typeof alg !== "string") {
		c.failure("Couldn't find algorithm in ID token header");
	}
	c.success("Extracted " + hashName + " from ID Token", { [hashName]: value, alg });
	return { hash: value, alg };
}

/** upstream: condition/client/ExtractAtHash.java */
export function extractAtHash(idToken: ParsedJwt, ...requirements: string[]): ExtractedHash {
	return extractHash("ExtractAtHash", "at_hash", idToken, requirements);
}

/** upstream: condition/client/ExtractCHash.java */
export function extractCHash(idToken: ParsedJwt, ...requirements: string[]): ExtractedHash {
	return extractHash("ExtractCHash", "c_hash", idToken, requirements);
}

/** upstream: condition/client/ExtractSHash.java */
export function extractSHash(idToken: ParsedJwt, ...requirements: string[]): ExtractedHash {
	return extractHash("ExtractSHash", "s_hash", idToken, requirements);
}

/** upstream: condition/client/AbstractValidateHash.java: the left half of the digest of `baseString` */
function validateHash(
	name: string,
	hashName: string,
	extracted: ExtractedHash,
	/** upstream getBaseStringBasedOnType: the value hashed, or the failure message when it is missing */
	base: { value: string | null; missing: string },
	requirements: string[],
): void {
	const c: Condition = condition(name, ...requirements);
	if (!extracted.alg) {
		c.failure("Alg is null or empty. Invalid");
	}
	if (!extracted.hash) {
		c.failure(hashName + " element is null or empty. Invalid");
	}
	const baseString = base.value;
	if (baseString == null) {
		c.failure(base.missing);
	}
	let digestAlgorithm: string;
	try {
		digestAlgorithm = getDigestAlgorithmForSigAlg(extracted.alg);
	} catch (e) {
		if (e instanceof InvalidAlgorithmException) {
			c.failure("Invalid algorithm", { alg: extracted.alg });
		}
		throw e;
	}
	// getBytes(US_ASCII): characters outside US-ASCII become '?'
	const ascii = Buffer.from(Array.from(baseString, (ch) => (ch.charCodeAt(0) < 0x80 ? ch : "?")).join(""), "latin1");
	const digest = createHash(digestAlgorithm.replace("-", "").toLowerCase()).update(ascii).digest();
	const expected = digest.subarray(0, digest.length / 2).toString("base64url");
	const fields = { expected_hash: expected, id_token_hash: extracted.hash, unhashed_value: baseString };
	if (extracted.hash !== expected) {
		c.failure("Invalid " + hashName + " in token", fields);
	}
	c.success(hashName + " validated successfully", fields);
}

/**
 * upstream: condition/client/ValidateAtHash.java
 *
 * UPSTREAM: without an access token (an at_hash in the id_token of response_type=id_token) upstream's @PreEnvironment
 * check fails before the condition runs ("couldn't find required object in environment before evaluation:
 * access_token"); here the condition fails with getBaseStringBasedOnType's message.
 */
export function validateAtHash(
	atHash: ExtractedHash,
	accessToken: AccessToken | null,
	...requirements: string[]
): void {
	const base = { value: accessToken?.value ?? null, missing: "Could not get access_token object..." };
	validateHash("ValidateAtHash", "at_hash", atHash, base, requirements);
}

/** upstream: condition/client/ValidateCHash.java (the code of the authorization response) */
export function validateCHash(cHash: ExtractedHash, code: string | null, ...requirements: string[]): void {
	const base = { value: code, missing: "Could not find authorization_endpoint_response.code" };
	validateHash("ValidateCHash", "c_hash", cHash, base, requirements);
}

/** upstream: condition/client/ValidateSHash.java */
export function validateSHash(sHash: ExtractedHash, state: string | null, ...requirements: string[]): void {
	validateHash("ValidateSHash", "s_hash", sHash, { value: state, missing: "Couldn't find state" }, requirements);
}

/**
 * The id_token is signed with a FAPI 2.0 algorithm (PS256, ES256, EdDSA, Ed25519).
 *
 * upstream: condition/client/FAPI2ValidateIdTokenSigningAlg.java (AbstractValidateIdTokenSigningAlg)
 */
export function fapi2ValidateIdTokenSigningAlg(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("FAPI2ValidateIdTokenSigningAlg", ...requirements);
	const permitted = ["PS256", "ES256", "EdDSA", "Ed25519"];
	let alg: string;
	try {
		alg = String(parseSignedJWT(idToken.value).header["alg"]);
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Error parsing ID Token", e);
		}
		throw e;
	}
	if (!permitted.includes(alg)) {
		c.failure("id_token must be signed with a permitted alg", { alg, permitted });
	}
	c.success("id_token was signed with a permitted algorithm", { alg, permitted });
}

/**
 * at_hash / c_hash are optional in an id_token from the token endpoint, but must be right when present.
 *
 * upstream: OIDCCServerTest.additionalTokenEndpointResponseValidation (the hash part)
 */
export function checkOptionalHashes(idToken: ParsedJwt, accessToken: AccessToken, code: string | null): void {
	const atHash = soft(() => extractAtHash(idToken, "OIDCC-3.3.2.11", "OIDCC-3.3.3.6"), "info");
	if (atHash === undefined) {
		skipped("ValidateAtHash", { object: "at_hash" }, "OIDCC-3.3.2.11");
	} else {
		soft(() => validateAtHash(atHash, accessToken, "OIDCC-3.3.2.11"));
	}
	const cHash = soft(() => extractCHash(idToken, "OIDCC-3.3.2.11", "OIDCC-3.3.3.6"), "info");
	if (cHash === undefined) {
		skipped("ValidateCHash", { object: "c_hash" }, "OIDCC-3.3.2.11");
	} else {
		soft(() => validateCHash(cHash, code, "OIDCC-3.3.2.11"));
	}
}

/** upstream: condition/client/EnsureIdTokenContainsKid.java */
export function ensureIdTokenContainsKid(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("EnsureIdTokenContainsKid", ...requirements);
	const kid = idToken.header["kid"];
	if (!kid) {
		c.failure("kid was not found in the ID token header");
	}
	c.success("kid was found in the ID token header", { kid });
}

/** upstream: condition/client/EnsureIdTokenSignatureIsRS256.java (AbstractCheckIdTokenSignatureAlgorithm) */
export function ensureIdTokenSignatureIsRS256(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("EnsureIdTokenSignatureIsRS256", ...requirements);
	const alg = idToken.header["alg"];
	if (!alg) {
		c.failure("alg not present in ID token header", { header: idToken.header });
	}
	if (alg !== "RS256") {
		c.failure('ID token signature algorithm is not "RS256"', { alg });
	}
	c.success('ID token was signed with "RS256" as expected');
}

/** upstream: condition/client/EnsureIdTokenDoesNotContainName.java */
export function ensureIdTokenDoesNotContainName(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("EnsureIdTokenDoesNotContainName", ...requirements);
	const name = stringClaim(idToken, "name");
	if (name != null) {
		// see discussion on certification email list, 10th March 2020
		c.failure(
			"Unexpectedly found name in id_token. The conformance suite did not request the 'name' claim is returned in the id_token and hence did not expect the server to include it. Technically this does not violate the specifications but it is likely a bug in the server and may result in user data being exposed in unintended ways.",
			{ name },
		);
	}
	c.success("name claim not found in id_token, which is expected as it was not requested to be returned there");
}

/** The claims a scope stands for (OIDCC 5.4; upstream AbstractVerifyScopesReturnedInClaims) */
export const SCOPE_STANDARD_CLAIMS = new Map<string, string[]>([
	["openid", ["sub"]],
	[
		"profile",
		[
			"name",
			"given_name",
			"family_name",
			"middle_name",
			"nickname",
			"profile",
			"picture",
			"website",
			"gender",
			"birthdate",
			"zoneinfo",
			"locale",
			"updated_at",
			"preferred_username",
		],
	],
	["email", ["email", "email_verified"]],
	["address", ["address"]],
	["phone", ["phone_number", "phone_number_verified"]],
	["offline_access", []],
]);

/**
 * Claims that may appear in an id_token without being requested.
 * UPSTREAM: a static list the condition adds the requested scopes' claims to, so they accumulate for the rest of
 * the process; kept for identical results.
 */
const idTokenValidClaims = [
	"iss",
	"sub",
	"aud",
	"exp",
	"iat",
	"auth_time",
	"nonce",
	"acr",
	"amr",
	"azp",
	"at_hash",
	"c_hash",
	"nbf",
	"jti",
	"sid",
	"s_hash",
	"openbanking_intent_id",
	"txn",
];

/** upstream: condition/client/EnsureIdTokenDoesNotContainNonRequestedClaims.java */
export function ensureIdTokenDoesNotContainNonRequestedClaims(
	idToken: ParsedJwt,
	request: Pick<AuthorizationRequest, "params">,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureIdTokenDoesNotContainNonRequestedClaims", ...requirements);
	const scope = typeof request.params["scope"] === "string" ? request.params["scope"] : null;
	if (scope) {
		const scopes = scope.split(" ");
		if (scopes.includes("openid")) {
			for (const s of scopes) {
				for (const name of SCOPE_STANDARD_CLAIMS.get(s) ?? []) {
					if (!idTokenValidClaims.includes(name)) {
						idTokenValidClaims.push(name);
					}
				}
			}
		}
	}
	let failed = false;
	for (const key of Object.keys(idToken.claims)) {
		if (!idTokenValidClaims.includes(key)) {
			failed = true;
			c.logFailure("id_token contains non-requested claim '" + key + "'");
		}
	}
	if (failed) {
		c.failure(
			"id_token contains non-requested claims. This may indicate the authorization server is returning data about the user that it should not, or that a specification has been wrongly implemented, or that it implements an extension the conformance suite is currently aware of.",
			{ requested_scope: scope, supplied: idToken.claims },
		);
	}
	c.success("no non-requested id_token claims found");
}

/** upstream: condition/client/EnsureIdTokenDoesNotContainEmailForScopeEmail.java */
export function ensureIdTokenDoesNotContainEmailForScopeEmail(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("EnsureIdTokenDoesNotContainEmailForScopeEmail", ...requirements);
	const email = stringClaim(idToken, "email");
	if (email != null) {
		// see discussion on certification email list, 10th March 2020
		c.failure(
			"Unexpectedly found email in id_token. The conformance suite did not request the 'email' claim is returned in the id_token and hence did not expect the server to include it; as per the spec link for this response_type scope=email is a short hand for 'please give me access to the user's email address in the userinfo response'. Technically returning unrequested claims does not violate the specifications but it could be a bug in the server and may result in user data being exposed in unintended ways if the relying party did not expect the email to be in the id_token, and then uses the id_token to provide proof of the authentication event to other parties.",
			{ email },
		);
	}
	c.success("email claim not found in id_token, which is expected as it was not requested to be returned there");
}

/**
 * auth_time (when both id_tokens have it) is the same in the id_tokens of two authorizations.
 *
 * upstream: condition/client/CheckIdTokenAuthTimeClaimsSameIfPresent.java
 */
export function checkIdTokenAuthTimeClaimsSameIfPresent(
	firstIdToken: ParsedJwt,
	secondIdToken: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckIdTokenAuthTimeClaimsSameIfPresent", ...requirements);
	const fields = { first_id_token: firstIdToken.claims, second_id_token: secondIdToken.claims };
	if ("auth_time" in firstIdToken.claims && "auth_time" in secondIdToken.claims) {
		const firstAuthTime = longClaim(firstIdToken, "auth_time");
		const authTime = longClaim(secondIdToken, "auth_time");
		if (firstAuthTime !== authTime) {
			c.failure("The id_tokens contain different auth_time claims, but must contain the same auth_time.", fields);
		}
		c.success("auth_time is the same in the second id_token", fields);
	} else {
		c.log(
			"auth_time cannot be checked as it is missing from the id_tokens for at least one of the authorizations",
			fields,
		);
	}
}

/**
 * The sub of the id_tokens of two authorizations is the same.
 *
 * upstream: condition/client/CheckIdTokenSubConsistentForSecondAuthorization.java
 */
export function checkIdTokenSubConsistentForSecondAuthorization(
	firstIdToken: ParsedJwt,
	secondIdToken: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckIdTokenSubConsistentForSecondAuthorization", ...requirements);
	const fields = { first_id_token: firstIdToken.claims, second_id_token: secondIdToken.claims };
	// UPSTREAM: Java's subFirst.equals(...) throws a NullPointerException when the first id_token has no sub
	if (stringClaim(firstIdToken, "sub") !== stringClaim(secondIdToken, "sub")) {
		c.failure(
			"The id_token from the first and second authorization contain different sub claims, but must contain the same sub.",
			fields,
		);
	}
	c.success("sub is the same in the second id_token", fields);
}

/** upstream: condition/client/CheckSecondIdTokenAuthTimeIsLaterIfPresent.java (prompt=login / max_age=1 must log in again) */
export function checkSecondIdTokenAuthTimeIsLaterIfPresent(
	firstIdToken: ParsedJwt,
	secondIdToken: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckSecondIdTokenAuthTimeIsLaterIfPresent", ...requirements);
	const first = firstIdToken.claims;
	const second = secondIdToken.claims;
	const logged = { first_id_token: first, second_id_token: second };
	if (Object.hasOwn(first, "auth_time") && Object.hasOwn(second, "auth_time")) {
		const firstAuthTime = Math.trunc(Number(first["auth_time"]));
		const secondAuthTime = Math.trunc(Number(second["auth_time"]));
		if (firstAuthTime === secondAuthTime) {
			c.failure(
				"prompt=login means the server was required to reauthenticate the user, the id_token from the second authorization incorrectly has the same auth_time as the id_token from the first authorization",
				logged,
			);
		}
		if (firstAuthTime > secondAuthTime) {
			c.failure(
				"The id_token from the second authorization incorrectly has an earlier auth_time than the id_token from the first authorization",
				logged,
			);
		}
		c.success("auth_time is later in the second id_token", logged);
	} else {
		c.log(
			"auth_time cannot be checked as it is missing from the id_tokens for at least one of the authorizations",
			logged,
		);
	}
}

/** upstream: condition/client/CheckIdTokenAuthTimeClaimPresentDueToMaxAge.java */
export function checkIdTokenAuthTimeClaimPresentDueToMaxAge(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("CheckIdTokenAuthTimeClaimPresentDueToMaxAge", ...requirements);
	if (!Object.hasOwn(idToken.claims, "auth_time")) {
		c.failure(
			"auth_time claim is missing from the id_token, but it is required for a authentication where the max_age parameter was used",
			{ id_token: idToken.claims },
		);
	}
	// no need to check type as ValidateIdToken did so
	c.success(
		"auth_time is present in the id_token, as required for a authentication where the max_age parameter was used",
		{ id_token: idToken.claims },
	);
}

/** upstream: condition/client/CheckIdTokenAuthTimeIsRecentIfPresent.java */
export function checkIdTokenAuthTimeIsRecentIfPresent(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("CheckIdTokenAuthTimeIsRecentIfPresent", ...requirements);
	if (!Object.hasOwn(idToken.claims, "auth_time")) {
		c.log("auth_time cannot be checked as it is missing from the id_token", { id_token: idToken.claims });
		return;
	}
	const authTime = Math.trunc(Number(idToken.claims["auth_time"]));
	// 5 minute allowable skew for testing
	if (Date.now() - TIME_SKEW_MILLIS - 1000 > authTime * 1000) {
		c.failure("id_token auth_time is older than 1 second (allowing 5 minutes skews)", {
			auth_time: new Date(authTime * 1000),
			now: new Date(),
		});
	}
	// ValidateIdToken already checked if auth_time is in the future
	c.success("auth_time in id_token is recent", { auth_time: new Date(authTime * 1000), now: new Date() });
}

/** upstream: condition/client/ValidateIdTokenACRClaimAgainstAcrValuesRequest.java */
export function validateIdTokenACRClaimAgainstAcrValuesRequest(
	idToken: ParsedJwt,
	request: Pick<AuthorizationRequest, "params">,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateIdTokenACRClaimAgainstAcrValuesRequest", ...requirements);
	const idTokenAcr = claim(idToken, "acr");
	const requestedAcrValues = request.params["acr_values"];
	if (requestedAcrValues == null) {
		c.failure(
			"authorization endpoint request did not contain acr_values; this is a problem with the conformance suite",
		);
	}
	if (idTokenAcr == null) {
		c.failure(
			"An acr value was requested using acr_values, so the server 'SHOULD' return an acr claim, but it did not.",
			{
				request: request.params,
				id_token: idToken,
			},
		);
	}
	if (typeof idTokenAcr !== "string") {
		c.failure("acr value in id_token must be a string", { id_token: idToken });
	}
	const requestedValues = String(requestedAcrValues).split(" ");
	if (requestedValues.includes(idTokenAcr)) {
		c.success("id_token acr claim contains one of the requested values", {
			requested_values: requestedValues,
			id_token_acr: idTokenAcr,
		});
		return;
	}
	c.failure("acr value in id_token is not (one of the) requested values", {
		requested_values: requestedValues,
		id_token_acr: idTokenAcr,
	});
}

/**
 * The id_token was signed with the algorithm the client registered for (id_token_signed_response_alg).
 *
 * upstream: condition/client/CheckIdTokenSignatureAlgorithm.java (AbstractCheckIdTokenSignatureAlgorithm)
 */
export function checkIdTokenSignatureAlgorithm(
	idToken: ParsedJwt,
	registrationRequest: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckIdTokenSignatureAlgorithm", ...requirements);
	const requestedAlg = registrationRequest["id_token_signed_response_alg"];
	if (typeof requestedAlg !== "string" || requestedAlg === "") {
		c.failure("id_token_signed_response_alg not found in dynamic registration request", {
			dynamic_registration_request: registrationRequest,
		});
	}
	const alg = idToken.header["alg"];
	if (typeof alg !== "string" || alg === "") {
		c.failure("alg not present in ID token header", { header: idToken.header });
	}
	if (alg !== requestedAlg) {
		c.failure('ID token signature algorithm is not "' + requestedAlg + '"', { alg });
	}
	c.success('ID token was signed with "' + requestedAlg + '" as expected');
}

/**
 * The claims of an id_token from a refresh token response against the original id_token (OIDCC-12.2): iss, sub, aud
 * and azp the same, auth_time (when present) the original, iat different.
 *
 * upstream: condition/client/CompareIdTokenClaims.java
 */
export function compareIdTokenClaims(
	firstIdToken: ParsedJwt,
	secondIdToken: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("CompareIdTokenClaims", ...requirements);
	const first = firstIdToken.claims;
	const second = secondIdToken.claims;
	const valuesForLog: Record<string, unknown> = {};

	for (const claimName of ["iss", "sub"]) {
		if (!hasClaim(first, claimName)) {
			c.failure("Initial id token does not contain a " + claimName + " claim", { claimName });
		}
		if (!hasClaim(second, claimName)) {
			c.failure("Second id token does not contain a " + claimName + " claim", { claimName });
		}
		if (first[claimName] !== second[claimName]) {
			c.failure("Claim values are not the same", { claim1: first[claimName], claim2: second[claimName] });
		}
		valuesForLog[claimName] = {
			first: first[claimName],
			second: second[claimName],
			note: "Values are expected to be equal",
		};
	}

	// its iat Claim MUST represent the time that the new ID Token is issued
	if (!hasClaim(first, "iat")) {
		c.failure("Initial id token does not contain an iat claim", { claimName: "iat" });
	}
	if (!hasClaim(second, "iat")) {
		c.failure("Second id token does not contain an iat claim", { claimName: "iat" });
	}
	if (first["iat"] === second["iat"]) {
		c.failure(
			"iat for the second id token MUST represent the time that the new ID Token is issued, cannot be the same as the initial id token",
			{ "First iat": first["iat"], "Second iat": second["iat"] },
		);
	}
	valuesForLog["iat"] = { first: first["iat"], second: second["iat"], note: "Values are expected to be different" };

	if (!hasClaim(first, "aud")) {
		c.failure("Initial id token does not contain an aud claim", { claimName: "aud" });
	}
	if (!hasClaim(second, "aud")) {
		c.failure("Second id token does not contain an aud claim", { claimName: "aud" });
	}
	const audMismatch =
		"aud Claim Value MUST be the same as in the ID Token issued when the original authentication occurred";
	if (Array.isArray(first["aud"])) {
		const claim1 = first["aud"] as string[];
		const claim2 = second["aud"] as string[];
		const set1 = new Set(claim1);
		const set2 = new Set(claim2);
		if (set1.size !== set2.size || [...set1].some((a) => !set2.has(a))) {
			c.failure(audMismatch, { "First aud": claim1, "Second aud": claim2 });
		}
		valuesForLog["aud"] = { first: claim1, second: claim2, note: "Values are expected to be equal" };
	} else {
		if (first["aud"] !== second["aud"]) {
			c.failure(audMismatch, { "First aud": first["aud"], "Second aud": second["aud"] });
		}
		valuesForLog["aud"] = { first: first["aud"], second: second["aud"], note: "Values are expected to be equal" };
	}

	// if the ID Token contains an auth_time Claim, its value MUST represent the time of the original authentication
	// UPSTREAM: nothing is checked when only the first id token has an auth_time
	if (hasClaim(second, "auth_time")) {
		const claim1 = first["auth_time"] ?? null;
		const claim2 = second["auth_time"] ?? null;
		if (claim2 !== claim1) {
			c.failure("auth_time claims are not the same", { claim1, claim2 });
		}
		valuesForLog["auth_time"] = { first: claim1, second: claim2, note: "Values are expected to be equal" };
	}

	// its azp Claim Value MUST be the same as in the ID Token issued when the original authentication occurred;
	// if no azp Claim was present in the original ID Token, one MUST NOT be present in the new ID Token
	if (!hasClaim(first, "azp") && hasClaim(second, "azp")) {
		c.failure("Second id token cannot contain an azp claim because the initial id token does not have an azp claim");
	}
	if (!hasClaim(first, "azp") && !hasClaim(second, "azp")) {
		valuesForLog["azp"] = "Id tokens do not contain azp claims";
	} else {
		const claim1 = first["azp"] ?? null;
		const claim2 = second["azp"] ?? null;
		if (claim1 !== claim2) {
			c.failure("azp claims are not the same", { claim1, claim2 });
		}
		valuesForLog["azp"] = { first: claim1, second: claim2, note: "Values are expected to be equal" };
	}

	c.success("Validated id token claims successfully", valuesForLog);
}

function hasClaim(claims: Record<string, unknown>, name: string): boolean {
	return Object.hasOwn(claims, name);
}

/**
 * The id_tokens from the authorization endpoint and the token endpoint of a hybrid flow are for the same user.
 *
 * upstream: condition/client/VerifyIdTokenSubConsistentHybridFlow.java
 */
export function verifyIdTokenSubConsistentHybridFlow(
	authorizationEndpointIdToken: ParsedJwt,
	tokenEndpointIdToken: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("VerifyIdTokenSubConsistentHybridFlow", ...requirements);
	const subAuth = stringClaim(authorizationEndpointIdToken, "sub");
	const subToken = stringClaim(tokenEndpointIdToken, "sub");
	// UPSTREAM: Java's subAuth.equals(...) throws a NullPointerException when the authorization endpoint id_token has
	// no sub; here the subs are simply compared
	if (subAuth !== subToken) {
		c.failure('"sub" in authorization endpoint id_token doesn\'t match with "sub" in token endpoint id_token', {
			sub_auth_endpoint: subAuth,
			sub_token_endpoint: subToken,
		});
	}
	c.success("authorization endpoint and token endpoint id_token have same sub", {
		sub_auth_endpoint: subAuth,
		sub_token_endpoint: subToken,
	});
}

/**
 * The claims of `claims` (the object named `claimsKey` in the messages) include the standard claims of every scope
 * of the authorization request.
 *
 * upstream: condition/client/AbstractVerifyScopesReturnedInClaims.java
 */
export function verifyScopesInClaims(
	c: Condition,
	claims: unknown,
	claimsKey: string,
	authorizationRequest: Pick<AuthorizationRequest, "params">,
): void {
	if (claims == null || typeof claims !== "object" || Array.isArray(claims)) {
		c.failure("'claims' in " + claimsKey + " is invalid", { claims: claims ?? null });
	}
	const scope = authorizationRequest.params["scope"];
	if (typeof scope !== "string" || scope === "") {
		c.failure("'scope' not found in authorization endpoint request");
	}
	const claimsSet = Object.keys(claims);
	const expectedScopeItems: string[] = [];
	for (const s of scope.split(" ")) {
		const items = SCOPE_STANDARD_CLAIMS.get(s);
		// UPSTREAM: an unknown scope makes Java throw a NullPointerException (addAll(null)); here a TypeError
		expectedScopeItems.push(...(items as string[]));
	}
	const missing = [...new Set(expectedScopeItems)].filter((item) => !claimsSet.includes(item));
	if (missing.length > 0) {
		c.failure(
			"'claims' in " +
				claimsKey +
				" doesn't contain all scope items of scope in authorization request(corresponds to scope standard claims)",
			{ actual_scope_items: claimsSet, expected_scope_items: expectedScopeItems, missing_items: missing },
		);
	}
	c.success(
		"'claims' in " +
			claimsKey +
			" contains all scope items of scope in authorization request (corresponds to scope standard claims)",
		{ actual_scope_items: claimsSet, expected_scope_items: expectedScopeItems },
	);
}

/**
 * For response_type=id_token (no access token for the userinfo endpoint) the id_token carries the claims of the
 * requested scopes.
 *
 * upstream: condition/client/VerifyScopesReturnedInAuthorizationEndpointIdToken.java (AbstractVerifyScopesReturnedInClaims)
 */
export function verifyScopesReturnedInAuthorizationEndpointIdToken(
	authorizationEndpointIdToken: ParsedJwt,
	authorizationRequest: Pick<AuthorizationRequest, "params">,
	...requirements: string[]
): void {
	const c: Condition = condition("VerifyScopesReturnedInAuthorizationEndpointIdToken", ...requirements);
	verifyScopesInClaims(c, authorizationEndpointIdToken.claims, "authorization_endpoint_id_token", authorizationRequest);
}

/** upstream: condition/client/EnsureIdTokenContainsName.java */
export function ensureIdTokenContainsName(idToken: ParsedJwt, ...requirements: string[]): void {
	const c: Condition = condition("EnsureIdTokenContainsName", ...requirements);
	const name = stringClaim(idToken, "name");
	if (!name) {
		c.failure("name not found in id_token");
	}
	c.success("Found name in id_token", { name });
}

/**
 * An id_token from the authorization endpoint must have at_hash when an access token is returned with it and c_hash
 * when a code is (OIDCC 3.3.2.11), and both must be right when present.
 *
 * upstream: OIDCCServerTest.performAuthorizationEndpointIdTokenValidation (the hash part)
 */
export function checkAuthorizationEndpointHashes(
	idToken: ParsedJwt,
	responseType: string,
	accessToken: AccessToken | null,
	code: string | null,
): void {
	const includes = (part: string) => responseType.split(" ").includes(part);
	const atHash = soft(() => extractAtHash(idToken, "OIDCC-3.3.2.11"), includes("token") ? "failure" : "info");
	if (atHash === undefined) {
		skipped("ValidateAtHash", { object: "at_hash" }, "OIDCC-3.3.2.11");
	} else {
		soft(() => validateAtHash(atHash, accessToken, "OIDCC-3.3.2.11"));
	}
	const cHash = soft(() => extractCHash(idToken, "OIDCC-3.3.2.11"), includes("code") ? "failure" : "info");
	if (cHash === undefined) {
		skipped("ValidateCHash", { object: "c_hash" }, "OIDCC-3.3.2.11");
	} else {
		soft(() => validateCHash(cHash, code, "OIDCC-3.3.2.11"));
	}
}

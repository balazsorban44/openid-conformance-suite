/**
 * The RP's client at the emulated OP: registered by the RP at the registration endpoint (dynamic_client) or taken
 * from the test configuration (static_client), with the metadata checks upstream runs on it (the client
 * validation conditions of condition/as/dynregistration) and the client authentication it registers with.
 */
import { randomInt } from "node:crypto";
import { checkDistinctKeyIdValueInClientJWKs, validateJwks } from "../op/jwks.ts";
import { extractJWKsFromStaticClientConfiguration } from "../op/registration.ts";
import { block, condition, logModule, skipped, soft, type Condition } from "../suite/conditions.ts";
import type { TestConfig } from "../suite/config.ts";
import { HttpError, request as httpRequest } from "../suite/http.ts";
import type { Jwks } from "../suite/jose.ts";
import type { IncomingRequest } from "../suite/server.ts";
import { isAsymmetricJWEAlgorithm } from "../suite/jose-jwe.ts";
import {
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
	isValidJWSAlgorithm,
	isAsymmetricJWSAlgorithm,
} from "../suite/jose-algorithms.ts";
import { parseJavaURI, URISyntaxException, isLocalhost } from "../suite/uri.ts";
import type { ServerMetadata } from "./discovery.ts";
import type { EmulatedOp } from "./op.ts";

/** The client as the emulated OP knows it (upstream env "client": the registration request plus what the OP added) */
export type RpClient = Record<string, unknown> & { client_id: string };

/** A value that is not of the JSON type a check reads it as (Gson / OIDFJSON UnexpectedJsonTypeException) */
class UnexpectedJsonType extends Error {
	override name = "UnexpectedJsonTypeException";
}

/** OIDFJSON.getString on a member: null when absent, the string, or UnexpectedJsonType */
function optString(o: Record<string, unknown>, name: string): string | null {
	const v = o[name];
	if (v === undefined) {
		return null;
	}
	if (typeof v !== "string") {
		throw new UnexpectedJsonType("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

/** Gson getAsJsonArray on a member: null when absent, the array, or a "Not a JSON Array" error */
function optArray(o: Record<string, unknown>, name: string): unknown[] | null {
	const v = o[name];
	if (v === undefined) {
		return null;
	}
	if (!Array.isArray(v)) {
		throw new NotAnArray("Not a JSON Array: " + JSON.stringify(v));
	}
	return v;
}

class NotAnArray extends Error {
	override name = "IllegalStateException";
}

/** The characters of the inclusive ranges */
function charRange(pairs: [string, string][]): string[] {
	return pairs.flatMap(([from, to]) =>
		Array.from({ length: to.charCodeAt(0) - from.charCodeAt(0) + 1 }, (_, i) =>
			String.fromCharCode(from.charCodeAt(0) + i),
		),
	);
}

function pickRandom(chars: string[], n: number): string {
	return Array.from({ length: n }, () => chars[randomInt(chars.length)]).join("");
}

/** Random VSCHARs (RFC 6749 Appendix A): letters, then digits, then punctuation (upstream RFC6749AppendixASyntaxUtils) */
export function generateVSChar(alphaCount: number, numberCount: number, punctuationCount: number): string {
	const letters = charRange([
		["a", "z"],
		["A", "Z"],
	]);
	const punctuation = charRange([
		[" ", "/"],
		[":", "@"],
		["[", "`"],
		["{", "~"],
	]);
	return (
		pickRandom(letters, alphaCount) +
		pickRandom(charRange([["0", "9"]]), numberCount) +
		pickRandom(punctuation, punctuationCount)
	);
}

/**
 * Random NQCHARs (RFC 6749 Appendix A: %x21 / %x23-5B / %x5D-7E): letters, then digits, then punctuation (upstream
 * RFC6749AppendixASyntaxUtils.generateNQChar: the DPoP nonces)
 */
export function generateNQChar(alphaCount: number, numberCount: number, punctuationCount: number): string {
	const letters = charRange([
		["a", "z"],
		["A", "Z"],
	]);
	const punctuation = charRange([
		["!", "!"],
		["#", "/"],
		[":", "@"],
		["[", "["],
		["]", "`"],
		["{", "~"],
	]);
	return (
		pickRandom(letters, alphaCount) +
		pickRandom(charRange([["0", "9"]]), numberCount) +
		pickRandom(punctuation, punctuationCount)
	);
}

// ---------------------------------------------------------------------------------------------------------------
// the registration request

/** upstream: condition/as/dynregistration/OIDCCExtractDynamicRegistrationRequest.java */
export function oidccExtractDynamicRegistrationRequest(req: IncomingRequest): Record<string, unknown> {
	const c: Condition = condition("OIDCCExtractDynamicRegistrationRequest");
	if (typeof req.body !== "string") {
		throw new UnexpectedJsonType("getString called on something that is not a string: null");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(req.body);
	} catch (e) {
		// UPSTREAM: JsonParser.parseString throws a JsonSyntaxException that ends the test
		throw new Error("Registration request body is not JSON: " + (e as Error).message, { cause: e });
	}
	if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error("Not a JSON Object: " + req.body);
	}
	const request = parsed as Record<string, unknown>;
	c.success("Extracted dynamic client registration request", { request });
	return request;
}

/** upstream: condition/as/dynregistration/EnsureRegistrationRequestContainsAtLeastOneContact.java */
export function ensureRegistrationRequestContainsAtLeastOneContact(
	request: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureRegistrationRequestContainsAtLeastOneContact", ...requirements);
	if (!("contacts" in request)) {
		c.failure("This application requires that registration requests contain at least one contact.");
	}
	const contacts = request["contacts"];
	if (!Array.isArray(contacts)) {
		c.failure(
			"This application requires that registration requests contain at least one contact. " +
				"Provided contacts is not encoded as a json array",
		);
	}
	if (contacts.length < 1) {
		c.failure(
			"This application requires that registration requests contain at least one contact. " +
				"Provided contacts array is empty",
		);
	}
	for (const element of contacts) {
		if (typeof element !== "string") {
			throw new UnexpectedJsonType("getString called on something that is not a string: " + JSON.stringify(element));
		}
		if (!element.includes("@")) {
			c.failure("Invalid contact. Only email addresses are expected in contacts", { contact: element });
		}
	}
	c.success("Registration request contains valid contacts", { contacts });
}

// ---------------------------------------------------------------------------------------------------------------
// client metadata (upstream AbstractClientValidationCondition accessors, as plain functions on the client)

function responseTypes(client: Record<string, unknown>): unknown[] {
	return optArray(client, "response_types") ?? ["code"];
}

/** True unless the client only uses the code response type (AbstractClientValidationCondition.hasImplicitResponseTypes) */
function hasImplicitResponseTypes(client: Record<string, unknown>): boolean {
	const types = responseTypes(client);
	return !(types.length === 1 && types[0] === "code");
}

function applicationType(client: Record<string, unknown>): string {
	return optString(client, "application_type") ?? "web";
}

/** name and name#lang values, keyed by lang ("" for the default) (getAllLogoUris / getAllClientUris / ...) */
function allLocalized(client: Record<string, unknown>, name: string): Map<string, string> {
	const uris = new Map<string, string>();
	for (const key of Object.keys(client)) {
		if (key === name) {
			uris.set("", optString(client, key) as string);
		} else if (key.startsWith(name + "#")) {
			uris.set(key.substring(name.length + 1), optString(client, key) as string);
		}
	}
	return uris;
}

/** The encryption enc, defaulting to A128CBC-HS256 when the alg is set (getIdTokenEncryptedResponseEnc, ...) */
function encryptionEnc(client: Record<string, unknown>, prefix: string, algName: string): string | null {
	const enc = optString(client, prefix + "_enc");
	if (enc != null) {
		return enc;
	}
	return optString(client, algName) != null ? "A128CBC-HS256" : null;
}

/** upstream: condition/as/dynregistration/ValidateClientGrantTypes.java */
export function validateClientGrantTypes(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateClientGrantTypes", ...requirements);
	const grantTypes = optArray(client, "grant_types") ?? ["authorization_code"];
	const types = responseTypes(client);
	let needImplicit = false;
	let needAuthorizationCode = false;
	for (const t of types) {
		if (typeof t !== "string") {
			throw new UnexpectedJsonType("getString called on something that is not a string: " + JSON.stringify(t));
		}
		const parts = new Set(t.split(" "));
		if (parts.has("code")) {
			needAuthorizationCode = true;
		}
		if (parts.has("token") || parts.has("id_token")) {
			needImplicit = true;
		}
	}
	const fields = { grant_types: grantTypes, response_types: types };
	if (needAuthorizationCode && !grantTypes.includes("authorization_code")) {
		c.failure("response_types require the use of authorization_code grant_type", fields);
	}
	if (needImplicit && !grantTypes.includes("implicit")) {
		c.failure("response_types require the use of implicit grant_type", fields);
	}
	c.success("grant_types match response_types", fields);
}

/** upstream: condition/as/dynregistration/OIDCCValidateClientRedirectUris.java */
export function oidccValidateClientRedirectUris(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("OIDCCValidateClientRedirectUris", ...requirements);
	let redirectUris: unknown[] | null;
	try {
		redirectUris = optArray(client, "redirect_uris");
	} catch (e) {
		if (e instanceof NotAnArray) {
			c.failureFrom("redirect_uris is not encoded as an array", e);
		}
		throw e;
	}
	if (redirectUris == null) {
		c.failure("redirect_uris is not set");
	}
	const errors: Record<string, unknown>[] = [];
	const appendError = (msg: string, details: Record<string, unknown>) => errors.push({ failure_reason: msg, details });
	let validUriCount = 0;
	for (const element of redirectUris) {
		if (typeof element !== "string") {
			throw new UnexpectedJsonType("getString called on something that is not a string: " + JSON.stringify(element));
		}
		const redirectUri = element;
		try {
			const uri = parseJavaURI(redirectUri);
			if (uri.fragment != null) {
				appendError("Invalid redirect uri. URI includes a fragment component.", { invalid_uri: redirectUri });
				continue;
			}
			// Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as
			// redirect_uris; they MUST NOT use localhost as the hostname
			if (applicationType(client) === "web" && hasImplicitResponseTypes(client)) {
				if (uri.scheme?.toLowerCase() === "http") {
					appendError(
						"Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris",
						{ uri: redirectUri },
					);
					continue;
				}
				// UPSTREAM: Java throws a NullPointerException when the URI has no (server-based) host
				if (isLocalhost(uri.host as string)) {
					appendError("Web Clients using the OAuth Implicit Grant Type MUST not use localhost as the hostname", {
						uri: redirectUri,
						host: uri.host,
					});
					continue;
				}
			}
			if (applicationType(client) === "native" && uri.scheme?.toLowerCase() === "http") {
				if (!isLocalhost(uri.host as string)) {
					// the python suite allows http when application type is native and the hostname is localhost
					appendError("http scheme is allowed only for native applications using localhost", { uri: redirectUri });
					continue;
				}
			}
			validUriCount++;
		} catch (e) {
			if (!(e instanceof URISyntaxException)) {
				throw e;
			}
			appendError("Invalid redirect uri: " + e.message, { invalid_uri: redirectUri });
		}
	}
	if (errors.length > 0) {
		c.failure("redirect_uris validation failed", { errors });
	}
	if (validUriCount === 0) {
		c.failure("At least one redirect_uri is required in dynamic client registration requests.");
	}
	c.success("Valid redirect_uri(s) provided in registration request", { redirect_uris: redirectUris });
}

/** upstream: condition/as/dynregistration/ValidateClientLogoUris.java */
export async function validateClientLogoUris(
	client: Record<string, unknown>,
	...requirements: string[]
): Promise<void> {
	const c: Condition = condition("ValidateClientLogoUris", ...requirements);
	const logoUris = allLocalized(client, "logo_uri");
	if (logoUris.size === 0) {
		c.success("Client does not contain any logo_uri");
		return;
	}
	const errors: Record<string, unknown>[] = [];
	const contentTypes: string[] = [];
	for (const uri of logoUris.values()) {
		// TODO(upstream) are data urls also valid logo_uri values?
		if (uri.startsWith("data:")) {
			if (uri.startsWith("data:image/")) {
				let end = uri.indexOf(";", 11);
				if (end === -1) {
					end = uri.indexOf(",", 11);
				}
				if (end === -1) {
					errors.push({ failure_reason: "Invalid data url format", details: { uri } });
				} else {
					contentTypes.push(uri + " : " + uri.substring(5, end));
				}
			}
			continue;
		}
		try {
			const res = await httpRequest(c.name, { url: uri, method: "HEAD" });
			if (res.status >= 400) {
				errors.push({
					failure_reason: "Http error",
					details: { uri, exception: res.status + " " + res.statusText + ": [no body]" },
				});
				continue;
			}
			const contentType = res.headers.get("content-type");
			if (contentType == null) {
				errors.push({ failure_reason: "Response does not contain a content-type header", details: { uri } });
				continue;
			}
			if (contentType.split("/")[0].trim().toLowerCase() === "image") {
				contentTypes.push(uri + " : " + contentType);
			} else {
				errors.push({
					failure_reason: "Invalid content type, content-type is not 'image'",
					details: { uri, content_type: contentType },
				});
			}
		} catch (e) {
			if (!(e instanceof HttpError)) {
				throw e;
			}
			errors.push({ failure_reason: "Http error", details: { uri, exception: e.message } });
		}
	}
	if (errors.length > 0) {
		c.failure("logo_uri validation failed", { errors });
	}
	c.success("Client contains valid logo_uri(s)", { logo_uri_content_types: contentTypes });
}

/** upstream: condition/as/dynregistration/AbstractValidateUrisBasedOnHttpStatusCodeOnly.java */
async function validateUrisBasedOnHttpStatusCodeOnly(
	name: string,
	metadataName: string,
	client: Record<string, unknown>,
	requirements: string[],
): Promise<void> {
	const c: Condition = condition(name, ...requirements);
	const uris = allLocalized(client, metadataName);
	if (uris.size === 0) {
		c.success("Client does not contain any " + metadataName);
		return;
	}
	const errors: Record<string, unknown>[] = [];
	const statusCodes: string[] = [];
	for (const uri of uris.values()) {
		try {
			// UPSTREAM: RestTemplate follows redirects, the suite's HTTP client does not
			const res = await httpRequest(c.name, { url: uri, method: "HEAD" });
			if (res.status >= 400) {
				errors.push({
					failure_reason: "Error checking " + metadataName,
					details: { uri, error_message: res.status + " " + res.statusText + ": [no body]" },
				});
				continue;
			}
			statusCodes.push(uri + " : " + res.status + " " + res.statusText);
		} catch (e) {
			if (!(e instanceof HttpError)) {
				throw e;
			}
			errors.push({ failure_reason: "Error checking " + metadataName, details: { uri, error_message: e.message } });
		}
	}
	if (errors.length > 0) {
		c.failure(metadataName + " validation failed", { errors, uri_status_codes: statusCodes });
	}
	c.success("Client contains valid " + metadataName + " value(s)", { uri_status_codes: statusCodes });
}

/** upstream: condition/as/dynregistration/ValidateClientUris.java */
export function validateClientUris(client: Record<string, unknown>, ...requirements: string[]): Promise<void> {
	return validateUrisBasedOnHttpStatusCodeOnly("ValidateClientUris", "client_uri", client, requirements);
}

/** upstream: condition/as/dynregistration/ValidateClientPolicyUris.java */
export function validateClientPolicyUris(client: Record<string, unknown>, ...requirements: string[]): Promise<void> {
	return validateUrisBasedOnHttpStatusCodeOnly("ValidateClientPolicyUris", "policy_uri", client, requirements);
}

/** upstream: condition/as/dynregistration/ValidateClientTosUris.java */
export function validateClientTosUris(client: Record<string, unknown>, ...requirements: string[]): Promise<void> {
	return validateUrisBasedOnHttpStatusCodeOnly("ValidateClientTosUris", "tos_uri", client, requirements);
}

/** upstream: condition/as/dynregistration/ValidateClientSubjectType.java */
export function validateClientSubjectType(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateClientSubjectType", ...requirements);
	const subjectType = optString(client, "subject_type");
	if (subjectType == null) {
		c.success("A subject_type was not provided");
		return;
	}
	if (subjectType === "public" || subjectType === "pairwise") {
		c.success("subject_type is valid", { subject_type: subjectType });
		return;
	}
	c.failure("Unexpected subject_type", { subject_type: subjectType });
}

/** upstream: condition/as/dynregistration/ValidateIdTokenSignedResponseAlg.java */
export function validateIdTokenSignedResponseAlg(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateIdTokenSignedResponseAlg", ...requirements);
	const alg = optString(client, "id_token_signed_response_alg") ?? "RS256";
	if (alg === "none") {
		if (hasImplicitResponseTypes(client)) {
			c.failure("none algorithm can only be used if only 'code' response type will be used");
		}
		c.success("none algorithm is allowed as only 'code' response type will be used");
		return;
	}
	if (isValidJWSAlgorithm(alg)) {
		c.success("id_token_signed_response_alg is one of the known algorithms", { alg });
		return;
	}
	c.failure("Unexpected id_token_signed_response_alg", { alg });
}

/** The shared body of EnsureIdTokenEncryptedResponseAlgIsSetIfEncIsSet and its userinfo / request object siblings */
function ensureEncryptedResponseAlgIsSetIfEncIsSet(
	name: string,
	prefix: "id_token_encrypted_response" | "userinfo_encrypted_response" | "request_object_encryption",
	client: Record<string, unknown>,
	requirements: string[],
): void {
	const c: Condition = condition(name, ...requirements);
	const algName = prefix + "_alg";
	const encName = prefix + "_enc";
	const enc = encryptionEnc(client, prefix, algName);
	const alg = optString(client, algName);
	if (enc != null && alg == null) {
		c.failure(`When ${encName} is included, ${algName} MUST also be provided.`, { [algName]: alg, [encName]: enc });
	}
	if (enc == null) {
		c.success(encName + " is not set");
		return;
	}
	c.success(algName + " is set", { [algName]: alg, [encName]: enc });
}

/** upstream: condition/as/dynregistration/EnsureIdTokenEncryptedResponseAlgIsSetIfEncIsSet.java */
export function ensureIdTokenEncryptedResponseAlgIsSetIfEncIsSet(
	client: Record<string, unknown>,
	...requirements: string[]
): void {
	ensureEncryptedResponseAlgIsSetIfEncIsSet(
		"EnsureIdTokenEncryptedResponseAlgIsSetIfEncIsSet",
		"id_token_encrypted_response",
		client,
		requirements,
	);
}

/** upstream: condition/as/dynregistration/EnsureUserinfoEncryptedResponseAlgIsSetIfEncIsSet.java */
export function ensureUserinfoEncryptedResponseAlgIsSetIfEncIsSet(
	client: Record<string, unknown>,
	...requirements: string[]
): void {
	ensureEncryptedResponseAlgIsSetIfEncIsSet(
		"EnsureUserinfoEncryptedResponseAlgIsSetIfEncIsSet",
		"userinfo_encrypted_response",
		client,
		requirements,
	);
}

/** upstream: condition/as/dynregistration/EnsureRequestObjectEncryptionAlgIsSetIfEncIsSet.java */
export function ensureRequestObjectEncryptionAlgIsSetIfEncIsSet(
	client: Record<string, unknown>,
	...requirements: string[]
): void {
	ensureEncryptedResponseAlgIsSetIfEncIsSet(
		"EnsureRequestObjectEncryptionAlgIsSetIfEncIsSet",
		"request_object_encryption",
		client,
		requirements,
	);
}

/** upstream: condition/as/dynregistration/ValidateUserinfoSignedResponseAlg.java */
export function validateUserinfoSignedResponseAlg(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateUserinfoSignedResponseAlg", ...requirements);
	const alg = optString(client, "userinfo_signed_response_alg");
	if (isValidJWSAlgorithm(alg)) {
		c.success("userinfo_signed_response_alg is one of the known algorithms", { alg });
		return;
	}
	c.failure("Unexpected userinfo_signed_response_alg", { alg });
}

/** upstream: condition/as/dynregistration/ValidateRequestObjectSigningAlg.java */
export function validateRequestObjectSigningAlg(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateRequestObjectSigningAlg", ...requirements);
	const alg = optString(client, "request_object_signing_alg");
	if (alg == null) {
		c.success("request_object_signing_alg is not set");
		return;
	}
	if (alg === "none") {
		c.success("request_object_signing_alg is 'none'");
		return;
	}
	if (isValidJWSAlgorithm(alg)) {
		c.success("request_object_signing_alg is one of the known algorithms", { alg });
		return;
	}
	c.failure("Unexpected request_object_signing_alg", { alg });
}

/** upstream: condition/as/dynregistration/ValidateTokenEndpointAuthSigningAlg.java */
export function validateTokenEndpointAuthSigningAlg(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateTokenEndpointAuthSigningAlg", ...requirements);
	const alg = optString(client, "token_endpoint_auth_signing_alg");
	if (alg == null) {
		c.success("token_endpoint_auth_signing_alg is not set");
		return;
	}
	if (alg === "none") {
		c.failure("'none' cannot be used for client authentication");
	}
	const method = optString(client, "token_endpoint_auth_method");
	if (method === "client_secret_jwt") {
		if (!JWS_FAMILY_HMAC_SHA.includes(alg)) {
			c.failure("Invalid algorithm for client_secret_jwt", { alg });
		}
		c.success("token_endpoint_auth_signing_alg is valid", { token_endpoint_auth_signing_alg: alg });
		return;
	}
	if (method === "private_key_jwt") {
		if (JWS_FAMILY_EC.includes(alg) || JWS_FAMILY_ED.includes(alg) || JWS_FAMILY_RSA.includes(alg)) {
			c.success("token_endpoint_auth_signing_alg is valid", { token_endpoint_auth_signing_alg: alg });
			return;
		}
		c.failure("Invalid algorithm for private_key_jwt", { token_endpoint_auth_signing_alg: alg });
	}
	c.success("token_endpoint_auth_signing_alg is set but it is not applicable to client authentication method", {
		token_endpoint_auth_signing_alg: alg,
		token_endpoint_auth_method: method,
	});
}

/** upstream: condition/as/dynregistration/ValidateDefaultMaxAge.java */
export function validateDefaultMaxAge(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateDefaultMaxAge", ...requirements);
	const v = client["default_max_age"];
	if (v === undefined) {
		c.success("default_max_age is not set");
		return;
	}
	if (typeof v !== "number") {
		c.failure("default_max_age is not encoded as a number", { default_max_age: v });
	}
	c.success("default_max_age is encoded as a number", { default_max_age: v });
}

/** upstream: condition/as/dynregistration/ValidateRequireAuthTime.java */
export function validateRequireAuthTime(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateRequireAuthTime", ...requirements);
	const v = client["require_auth_time"];
	if (typeof v !== "boolean") {
		c.failure("require_auth_time is not encoded as a boolean", { require_auth_time: v });
	}
	c.success("require_auth_time is encoded as a boolean", { require_auth_time: v });
}

/** upstream: condition/as/dynregistration/ValidateDefaultAcrValues.java */
export function validateDefaultAcrValues(
	client: Record<string, unknown>,
	server: ServerMetadata,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateDefaultAcrValues", ...requirements);
	const values = client["default_acr_values"];
	if (!Array.isArray(values)) {
		c.failure("default_acr_values is not encoded as a json array", { default_acr_values: values });
	}
	const supportedElement = server["acr_values_supported"];
	const supported = Array.isArray(supportedElement) ? new Set(supportedElement.map(String)) : null;
	for (const element of values) {
		if (typeof element !== "string") {
			c.failure("default_acr_values contains a value that is not encoded as a string", { element });
		}
		if (supported != null && !supported.has(element)) {
			c.failure("acr value is not one of the supported ones", {
				acr_values_supported: supportedElement,
				offending_value: element,
			});
		}
	}
	c.success("default_acr_values is valid", { default_acr_values: values });
}

/** upstream: condition/as/dynregistration/ValidateInitiateLoginUri.java */
export function validateInitiateLoginUri(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateInitiateLoginUri", ...requirements);
	const v = client["initiate_login_uri"];
	if (typeof v !== "string") {
		c.failure("initiate_login_uri is not encoded as a string", { initiate_login_uri: v });
	}
	let scheme: string | null;
	try {
		scheme = parseJavaURI(v).scheme;
	} catch (e) {
		if (!(e instanceof URISyntaxException)) {
			throw e;
		}
		c.failure("initiate_login_uri is not a valid URI", { initiate_login_uri: v });
	}
	if (scheme?.toLowerCase() === "https") {
		c.success("initiate_login_uri is valid", { initiate_login_uri: v });
		return;
	}
	c.failure("initiate_login_uri is not a https URI", { initiate_login_uri: v });
}

/** upstream: condition/as/dynregistration/ValidateRequestUris.java */
export function validateRequestUris(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateRequestUris", ...requirements);
	const uris = client["request_uris"];
	if (!Array.isArray(uris)) {
		c.failure("request_uris is not encoded as a json array", { request_uris: uris });
	}
	for (const element of uris) {
		if (typeof element !== "string") {
			c.failure("request_uris contains a value that is not encoded as a string", { element });
		}
		try {
			parseJavaURI(element);
		} catch (e) {
			if (!(e instanceof URISyntaxException)) {
				throw e;
			}
			c.failure("request_uris contains a value that is not a valid URI", { element });
		}
	}
	c.success("request_uris is valid", { request_uris: uris });
}

/**
 * The client metadata checks (used for a registration request and for a static client); jwks / jwks_uri are
 * checked by {@link processAndValidateClientJwks}. A check whose metadata is absent is skipped, as upstream.
 *
 * upstream: AbstractOIDCCClientTest.validateClientMetadata
 */
export async function validateClientMetadata(client: Record<string, unknown>, server: ServerMetadata): Promise<void> {
	const whenPresent = (name: string, path: string, check: () => void) => {
		if (client[path] === undefined) {
			skipped(name, { element: ["client", path] }, "OIDCR-2");
			return;
		}
		soft(check);
	};
	soft(() => validateClientGrantTypes(client, "OIDCR-2"));
	soft(() => oidccValidateClientRedirectUris(client, "OIDCR-2"));
	await soft(() => validateClientLogoUris(client, "OIDCR-2"));
	await soft(() => validateClientUris(client, "OIDCR-2"));
	await soft(() => validateClientPolicyUris(client, "OIDCR-2"));
	await soft(() => validateClientTosUris(client, "OIDCR-2"));
	soft(() => validateClientSubjectType(client, "OIDCR-2"));
	whenPresent("ValidateIdTokenSignedResponseAlg", "id_token_signed_response_alg", () =>
		validateIdTokenSignedResponseAlg(client, "OIDCR-2"),
	);
	soft(() => ensureIdTokenEncryptedResponseAlgIsSetIfEncIsSet(client, "OIDCR-2"));
	whenPresent("ValidateUserinfoSignedResponseAlg", "userinfo_signed_response_alg", () =>
		validateUserinfoSignedResponseAlg(client, "OIDCR-2"),
	);
	soft(() => ensureUserinfoEncryptedResponseAlgIsSetIfEncIsSet(client, "OIDCR-2"));
	whenPresent("ValidateRequestObjectSigningAlg", "request_object_signing_alg", () =>
		validateRequestObjectSigningAlg(client, "OIDCR-2"),
	);
	soft(() => ensureRequestObjectEncryptionAlgIsSetIfEncIsSet(client, "OIDCR-2"));
	// token_endpoint_auth_method is not validated as the emulated OP overrides it anyway
	whenPresent("ValidateTokenEndpointAuthSigningAlg", "token_endpoint_auth_signing_alg", () =>
		validateTokenEndpointAuthSigningAlg(client, "OIDCR-2"),
	);
	soft(() => validateDefaultMaxAge(client, "OIDCR-2"), "warning");
	whenPresent("ValidateRequireAuthTime", "require_auth_time", () => validateRequireAuthTime(client, "OIDCR-2"));
	whenPresent("ValidateDefaultAcrValues", "default_acr_values", () =>
		validateDefaultAcrValues(client, server, "OIDCR-2"),
	);
	whenPresent("ValidateInitiateLoginUri", "initiate_login_uri", () => validateInitiateLoginUri(client, "OIDCR-2"));
	whenPresent("ValidateRequestUris", "request_uris", () => validateRequestUris(client, "OIDCR-2"));
}

/** upstream: condition/as/dynregistration/ValidateClientRegistrationRequestSectorIdentifierUri.java */
export async function validateClientRegistrationRequestSectorIdentifierUri(
	registrationRequest: Record<string, unknown>,
	...requirements: string[]
): Promise<void> {
	const c: Condition = condition("ValidateClientRegistrationRequestSectorIdentifierUri", ...requirements);
	const uri = optString(registrationRequest, "sector_identifier_uri");
	if (uri == null) {
		c.success("A sector_identifier_uri was not provided");
		return;
	}
	if (!uri.toLowerCase().startsWith("https://")) {
		c.failure("sector_identifier_uri MUST be a URL using the https scheme", { uri });
	}
	let body: string | null = "";
	try {
		// UPSTREAM: RestTemplate follows redirects, the suite's HTTP client does not
		const res = await httpRequest(c.name, { url: uri, method: "GET" });
		if (res.status >= 400) {
			c.failure("Failed to retrieve sector_identifier_uri", {
				uri,
				error: res.status + " " + res.statusText + ": " + (res.body ? '"' + res.body + '"' : "[no body]"),
			});
		}
		body = res.body;
	} catch (e) {
		if (e instanceof HttpError) {
			c.failureFrom("Failed to retrieve sector_identifier_uri", e, { uri, error: e.message });
		}
		throw e;
	}
	if (body == null || body.length === 0) {
		c.failure("Invalid sector_identifier_uri. When fetching sector_identifier_uri the server returned an empty body", {
			uri,
		});
	}
	let fromSectorIdentifierUri: unknown;
	try {
		fromSectorIdentifierUri = JSON.parse(body);
	} catch (e) {
		c.failureFrom("sector_identifier_uri response does not contain a valid json", e, { uri, response: body });
	}
	if (!Array.isArray(fromSectorIdentifierUri)) {
		c.failure("sector_identifier_uri response does not contain a json array", { uri, response: body });
	}
	let redirectUris: unknown[] | null;
	try {
		redirectUris = optArray(registrationRequest, "redirect_uris");
	} catch (e) {
		if (e instanceof NotAnArray) {
			c.failure("redirect_uris is not encoded as a json array");
		}
		throw e;
	}
	if (redirectUris == null) {
		c.failure("redirect_uris is empty");
	}
	const listed = new Set(fromSectorIdentifierUri.map(String));
	for (const redirectUri of new Set(redirectUris.map(String))) {
		// The values registered in redirect_uris MUST be included in the elements of the array, or registration
		// MUST fail.
		if (!listed.has(redirectUri)) {
			c.failure("A redirect_uri provided in registration request is not found in sector_identifier_uri response", {
				redirect_uri: redirectUri,
				sector_identifier_uri_response: fromSectorIdentifierUri,
			});
		}
	}
	c.success(
		"sector_identifier_uri response validated successfully. All uris in redirect_uris are included in sector_identifier_uri response",
	);
}

// ---------------------------------------------------------------------------------------------------------------
// registering the client

/** upstream: condition/as/dynregistration/OIDCCRegisterClient.java */
export function oidccRegisterClient(request: Record<string, unknown>): RpClient {
	const client = { ...structuredClone(request), client_id: "client_" + generateVSChar(15, 5, 5) } as RpClient;
	condition("OIDCCRegisterClient").success("Registered client", { client });
	return client;
}

/** upstream: condition/as/dynregistration/OIDCCCreateClientSecretForDynamicClient.java */
export function oidccCreateClientSecretForDynamicClient(client: RpClient): void {
	// HS256 requires at least 64 characters
	const secret = "secret_" + generateVSChar(50, 10, 5);
	client["client_secret"] = secret;
	client["client_secret_expires_at"] = 0;
	condition("OIDCCCreateClientSecretForDynamicClient").log("Set the secret for registered client", {
		client_secret: secret,
	});
}

const ENSURE_TOKEN_ENDPOINT_AUTH_METHOD: Record<string, string> = {
	client_secret_basic: "EnsureTokenEndPointAuthMethodIsClientSecretBasic",
	client_secret_post: "EnsureTokenEndPointAuthMethodIsClientSecretPost",
	client_secret_jwt: "EnsureTokenEndPointAuthMethodIsClientSecretJwt",
	private_key_jwt: "EnsureTokenEndPointAuthMethodIsPrivateKeyJwt",
	none: "EnsureTokenEndPointAuthMethodIsNone",
	tls_client_auth: "EnsureTokenEndPointAuthMethodIsTlsClientAuth",
	self_signed_tls_client_auth: "EnsureTokenEndPointAuthMethodIsSelfSignedTlsClientAuth",
};

/**
 * The client registered for the authentication method the test requires.
 *
 * upstream: condition/as/dynregistration/AbstractEnsureTokenEndPointAuthMethod.java,
 * EnsureTokenEndPointAuthMethodIsClientSecretBasic.java, EnsureTokenEndPointAuthMethodIsClientSecretPost.java,
 * EnsureTokenEndPointAuthMethodIsClientSecretJwt.java, EnsureTokenEndPointAuthMethodIsPrivateKeyJwt.java,
 * EnsureTokenEndPointAuthMethodIsNone.java, EnsureTokenEndPointAuthMethodIsTlsClientAuth.java,
 * EnsureTokenEndPointAuthMethodIsSelfSignedTlsClientAuth.java
 */
export function ensureTokenEndPointAuthMethodIs(client: RpClient, expected: string): void {
	const c: Condition = condition(ENSURE_TOKEN_ENDPOINT_AUTH_METHOD[expected] ?? "EnsureTokenEndPointAuthMethod");
	if (!("token_endpoint_auth_method" in client)) {
		c.log(
			`token_endpoint_auth_method is not set, client will be registered using '${expected}' as required by this test`,
		);
		return;
	}
	const method = optString(client, "token_endpoint_auth_method");
	if (method === expected) {
		c.success(`token_endpoint_auth_method is '${expected}' as expected`);
		return;
	}
	c.failure(`token_endpoint_auth_method is set to '${method}' but this test requires '${expected}'`, {
		expected,
		actual: method,
	});
}

/**
 * What the registration endpoint adds for the variant's client authentication.
 *
 * upstream: sequence/as/OIDCCRegisterClientWithClientSecret.java, OIDCCRegisterClientWithClientSecretBasic.java,
 * OIDCCRegisterClientWithClientSecretPost.java, OIDCCRegisterClientWithNone.java
 */
export function registerClientWithClientAuth(client: RpClient, clientAuthType: string): void {
	if (clientAuthType === "client_secret_basic" || clientAuthType === "client_secret_post") {
		oidccCreateClientSecretForDynamicClient(client);
		ensureTokenEndPointAuthMethodIs(client, clientAuthType);
	} else if (clientAuthType === "none") {
		ensureTokenEndPointAuthMethodIs(client, "none");
	} else {
		throw new Error(`TODO(port): client_auth_type=${clientAuthType} is not supported by the emulated OP yet`);
	}
}

/** upstream: condition/as/dynregistration/SetClientIdTokenSignedResponseAlgToNone.java */
export function setClientIdTokenSignedResponseAlgToNone(client: RpClient): void {
	client["id_token_signed_response_alg"] = "none";
	condition("SetClientIdTokenSignedResponseAlgToNone").log(
		"Set id_token_signed_response_alg to none for the registered client",
		{ client },
	);
}

/** upstream: condition/as/dynregistration/SetClientIdTokenSignedResponseAlgToRS256.java */
export function setClientIdTokenSignedResponseAlgToRS256(client: RpClient): void {
	client["id_token_signed_response_alg"] = "RS256";
	condition("SetClientIdTokenSignedResponseAlgToRS256").log(
		"Set id_token_signed_response_alg to RS256 for the registered client",
		{ client },
	);
}

/** upstream: condition/as/dynregistration/SetClientGrantTypesToAuthorizationCodeOnly.java */
export function setClientGrantTypesToAuthorizationCodeOnly(client: RpClient): void {
	client["grant_types"] = ["authorization_code"];
	condition("SetClientGrantTypesToAuthorizationCodeOnly").log(
		"Set grant_types to ['authorization_code'] for the registered client",
		{ client },
	);
}

/** upstream: condition/as/dynregistration/SetClientIdTokenSignedResponseAlgToServerSigningAlg.java */
export function setClientIdTokenSignedResponseAlgToServerSigningAlg(client: RpClient, signingAlg: string): void {
	client["id_token_signed_response_alg"] = signingAlg;
	condition("SetClientIdTokenSignedResponseAlgToServerSigningAlg").log(
		"Set id_token_signed_response_alg for the registered client",
		{ id_token_signed_response_alg: signingAlg },
	);
}

// ---------------------------------------------------------------------------------------------------------------
// the client's keys

/**
 * Whether the client must publish keys: private_key_jwt / self_signed_tls_client_auth, asymmetrically signed
 * request objects, asymmetric id_token / userinfo encryption.
 *
 * upstream: AbstractOIDCCClientTest.isClientJwksNeeded
 */
export function isClientJwksNeeded(
	client: Record<string, unknown>,
	clientAuthType: string,
	requestType: string,
): boolean {
	if (clientAuthType === "private_key_jwt" || clientAuthType === "self_signed_tls_client_auth") {
		return true;
	}
	if (requestType === "request_object" || requestType === "request_uri") {
		const alg = optString(client, "request_object_signing_alg");
		// without request_object_signing_alg any algorithm may be used: whether keys are needed is only known
		// when a request object arrives
		if (alg != null && alg !== "none" && isAsymmetricJWSAlgorithm(alg)) {
			return true;
		}
	}
	const idTokenEncAlg = optString(client, "id_token_encrypted_response_alg");
	if (idTokenEncAlg != null && isAsymmetricJWEAlgorithm(idTokenEncAlg)) {
		return true;
	}
	const userinfoEncAlg = optString(client, "userinfo_encrypted_response_alg");
	return userinfoEncAlg != null && isAsymmetricJWEAlgorithm(userinfoEncAlg);
}

/** upstream: condition/as/EnsureClientHasJwksOrJwksUri.java */
export function ensureClientHasJwksOrJwksUri(client: Record<string, unknown>): void {
	const c: Condition = condition("EnsureClientHasJwksOrJwksUri");
	if (client["jwks"] == null && client["jwks_uri"] == null) {
		c.failure(
			"Client must have either jwks or jwks_uri set. This is typically required " +
				"when client authentication type is private_key_jwt " +
				" or self_signed_tls_client_auth, " +
				"or when an asymmetric algorithm is used for request_object_signing_alg, " +
				"id_token_encrypted_response_alg or userinfo_encrypted_response_alg.",
			{ client },
		);
	}
	c.success("Client has jwks or jwks_uri", { client });
}

/** upstream: condition/as/EnsureClientDoesNotHaveBothJwksAndJwksUri.java */
export function ensureClientDoesNotHaveBothJwksAndJwksUri(
	client: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureClientDoesNotHaveBothJwksAndJwksUri", ...requirements);
	if (client["jwks"] != null && client["jwks_uri"] != null) {
		c.failure("Client cannot have both jwks and jwks_uri at the same time", { client });
	}
	c.success("Client does not have both jwks and jwks_uri set", { client });
}

/** upstream: condition/as/FetchClientKeys.java (the client's jwks_uri, stored as client.jwks) */
export async function fetchClientKeys(client: Record<string, unknown>, ...requirements: string[]): Promise<void> {
	const c: Condition = condition("FetchClientKeys", ...requirements);
	const jwksUri = optString(client, "jwks_uri");
	if ("jwks" in client) {
		c.failure("Client already has a jwks", { client });
	}
	if (!jwksUri) {
		c.failure("Didn't find a jwks_uri in client configuration");
	}
	c.log("Fetching client keys", { jwks_uri: jwksUri });
	let body: string | null;
	try {
		const res = await httpRequest(c.name, { url: jwksUri, method: "GET" });
		if (res.status >= 400) {
			c.failureFrom("Unable to fetch client keys from " + jwksUri, new Error(res.status + " " + res.statusText));
		}
		body = res.body;
	} catch (e) {
		if (e instanceof HttpError) {
			c.failureFrom("Unable to fetch client keys from " + jwksUri, e);
		}
		throw e;
	}
	c.log("Found JWK set string", { jwk_string: body });
	let jwkSet: unknown;
	try {
		jwkSet = JSON.parse(body ?? "");
	} catch (e) {
		c.failureFrom("Client JWKs set string is not JSON", e);
	}
	if (jwkSet == null || typeof jwkSet !== "object" || Array.isArray(jwkSet)) {
		c.failure("Client JWKs set string is not JSON");
	}
	client["jwks"] = jwkSet;
	c.success("Downloaded and added client JWK set to client", { client });
}

/**
 * The client's own keys: present when needed, not both jwks and jwks_uri, fetched from jwks_uri, then validated
 * like any JWK set that enters the suite. Returns the client's public keys (upstream "client_public_jwks").
 *
 * upstream: AbstractOIDCCClientTest.processAndValidateClientJwks (fetchClientJwksFromJwksUri, validateClientJwks)
 */
export async function processAndValidateClientJwks(
	client: Record<string, unknown>,
	clientAuthType: string,
	requestType: string,
): Promise<Jwks | null> {
	if (isClientJwksNeeded(client, clientAuthType, requestType)) {
		ensureClientHasJwksOrJwksUri(client);
	}
	ensureClientDoesNotHaveBothJwksAndJwksUri(client, "OIDCR-2");
	if (client["jwks_uri"] === undefined) {
		skipped("FetchClientKeys", { element: ["client", "jwks_uri"] }, "OIDCC-10.1.1", "OIDCC-10.2.1");
	} else {
		await fetchClientKeys(client, "OIDCC-10.1.1", "OIDCC-10.2.1");
	}
	if (client["jwks"] == null) {
		return null;
	}
	const keys = extractJWKsFromStaticClientConfiguration(client["jwks"]);
	await validateJwks(client["jwks"] as Jwks, "client configuration", { requirements: ["RFC7517-1.1"] });
	soft(() => checkDistinctKeyIdValueInClientJWKs(client["jwks"] as Jwks, "RFC7517-4.5"));
	return keys.publicJwks;
}

/**
 * The static client of the test configuration; single valued redirect_uri / post_logout_redirect_uri become the
 * registration arrays.
 *
 * upstream: condition/as/OIDCCGetStaticClientConfigurationForRPTests.java
 */
export function oidccGetStaticClientConfigurationForRPTests(config: TestConfig): RpClient {
	const c: Condition = condition("OIDCCGetStaticClientConfigurationForRPTests");
	const configured = config["client"];
	if (configured == null || typeof configured !== "object" || Array.isArray(configured)) {
		c.failure("Definition for client not present in supplied configuration");
	}
	const client = structuredClone(configured) as Record<string, unknown>;
	for (const single of ["redirect_uri", "post_logout_redirect_uri"]) {
		if (client[single] != null) {
			const value = optString(client, single) as string;
			delete client[single];
			client[single + "s"] = [value];
		}
	}
	c.success("Found a static client object", client);
	return client as RpClient;
}

// ---------------------------------------------------------------------------------------------------------------
// the registration endpoint

/**
 * The registration request: its metadata is validated (a failing check is recorded, registration continues), the
 * client is registered with a client_id (and secret for the client_secret_* methods), `registrationSteps` (the
 * module's additional metadata, e.g. id_token_signed_response_alg none) are applied, the client's keys checked and
 * the id_token signing algorithm chosen. The response is the client (201).
 *
 * upstream: AbstractOIDCCClientTest.handleRegistrationEndpointRequest (validateRegistrationRequest, registerClient)
 */
export async function handleRegistrationRequest(
	op: EmulatedOp,
	req: IncomingRequest,
): Promise<{ response: Response; client: RpClient }> {
	return block("Registration endpoint", async () => {
		const request = oidccExtractDynamicRegistrationRequest(req);
		// because the python suite requires this
		soft(() => ensureRegistrationRequestContainsAtLeastOneContact(request), "info");
		await (op.options.validateClientMetadata ?? validateClientMetadata)(request, op.metadata);
		op.options.checkClientMetadata?.(request);
		await soft(() => validateClientRegistrationRequestSectorIdentifierUri(request, "OIDCR-2", "OIDCR-5"));

		const client = oidccRegisterClient(request);
		registerClientWithClientAuth(client, op.clientAuthType);
		op.options.registrationSteps?.(client);
		op.clientPublicJwks = await processAndValidateClientJwks(client, op.clientAuthType, op.variant.request_type);
		op.client = client;
		// the id_token signing algorithm is chosen after registration (the client's id_token_signed_response_alg)
		op.signingAlg = op.chooseSigningAlg(client);
		setClientIdTokenSignedResponseAlgToServerSigningAlg(client, op.signingAlg);
		return { response: Response.json(client, { status: 201 }), client };
	});
}

// ---------------------------------------------------------------------------------------------------------------
// 3rd party initiated login

/** upstream: condition/as/dynregistration/ValidateClientInitiateLoginUri.java */
export function validateClientInitiateLoginUri(client: Record<string, unknown>, ...requirements: string[]): void {
	const c: Condition = condition("ValidateClientInitiateLoginUri", ...requirements);
	if (!("initiate_login_uri" in client)) {
		c.failure("Client configuration does not contain required 'initiate_login_uri'");
	}
	const initiateLoginUri = client["initiate_login_uri"];
	if (typeof initiateLoginUri !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(initiateLoginUri));
	}
	let url: URL;
	try {
		url = new URL(initiateLoginUri);
	} catch {
		c.failure("initiate_login_uri does not contain a valid URL", { initiate_login_uri: initiateLoginUri });
	}
	if (url.protocol !== "https:") {
		c.failure("initiate_login_uri does not use https", { initiate_login_uri: initiateLoginUri });
	}
	// Java's URL.toString() returns the original external form
	c.success("valid initiate_login_uri", { initiate_login_uri: initiateLoginUri });
}

/**
 * The client's initiate_login_uri with the OP's issuer (OIDCC-4: iss is required), where the OP sends the user to
 * start a 3rd party initiated login; logged as upstream's module does before the user is sent there.
 *
 * (upstream OIDCCClient3rdPartyInitiatedLoginTest.validateClientMetadata's background task)
 */
export function initiateLoginRedirect(client: RpClient, issuer: string): string {
	const builder = new URL(client["initiate_login_uri"] as string);
	builder.searchParams.append("iss", issuer);
	const redirectTo = builder.toString();
	logModule({
		msg: "Redirecting user to initiate_login_uri - press 'Proceed with test' to continue",
		redirect_to: redirectTo,
		http: "redirect",
	});
	return redirectTo;
}

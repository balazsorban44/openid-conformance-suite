/**
 * The emulated OP's authorization endpoint: the checks upstream runs on the RP's authorization request (openid
 * scope, client_id, registered redirect_uri, response_type, nonce, PKCE, claims parameter) and the response
 * (code / id_token / token, redirected to the RP by query, fragment or form_post).
 */
import { randomAlphanumeric } from "../suite/random.ts";
import { block, condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import type { ParsedJwt } from "../suite/jose.ts";
import { escapeHtml } from "../suite/log.ts";
import { htmlResponse, type IncomingRequest } from "../suite/server.ts";
import {
	encodeQueryParam,
	toUriString,
	requireHttpsIfWebAndResponseTypeNotCode,
	dontAllowHttpIfNativeAndNotLocalhost,
} from "../suite/uri.ts";
import { calculateCHash, createIdToken } from "./id-token.ts";
import { OAuthError, type EmulatedOp, type RpVariant } from "./op.ts";
import type { RpClient } from "./registration.ts";
import {
	checkForUnexpectedClaimsInRequestObject,
	checkRequestObject,
	extractRequestObjectFromAuthorizationRequest,
} from "./request-object.ts";
import { generateAccessToken } from "./token.ts";

/** The authorization request parameters (upstream "authorization_endpoint_http_request_params" / the effective request) */
export type AuthorizationParams = Record<string, unknown>;

/** What the authorization request established (upstream env entries the later endpoints read) */
export interface AuthorizationState {
	/** upstream "effective_authorization_endpoint_request" */
	params: AuthorizationParams;
	/** upstream "scope" (ExtractRequestedScopes) */
	scope: string;
	/** upstream "nonce", null when the RP sent none */
	nonce: string | null;
	/** upstream "authorization_endpoint_request_redirect_uri" */
	redirectUri: string;
	/** upstream "authorization_code" (response types with code) */
	code: string | null;
	cHash: string | null;
	/** upstream "code_challenge" / "code_challenge_method" */
	codeChallenge: { code_challenge: string; code_challenge_method: string } | null;
	/** upstream "auth_time" (set once the response is sent) */
	authTime: number | null;
}

/** A parameter read as a string (OIDFJSON.getString): null when absent, an error when repeated */
function param(params: AuthorizationParams, name: string): string | null {
	const v = params[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

// ---------------------------------------------------------------------------------------------------------------
// the request

/** upstream: condition/as/EnsureRequestDoesNotContainRequestObject.java */
export function ensureRequestDoesNotContainRequestObject(params: AuthorizationParams, ...requirements: string[]): void {
	const c: Condition = condition("EnsureRequestDoesNotContainRequestObject", ...requirements);
	const request = param(params, "request");
	if (request) {
		c.failure("request parameter is not allowed", { request });
	}
	c.success("Request does not contain a request parameter");
}

/** upstream: condition/as/EnsureAuthorizationHttpRequestContainsOpenIDScope.java */
export function ensureAuthorizationHttpRequestContainsOpenIDScope(
	params: AuthorizationParams,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureAuthorizationHttpRequestContainsOpenIDScope", ...requirements);
	const scope = param(params, "scope");
	if (!scope) {
		c.failure("Http request parameters don't contain a scope parameter", { request_parameters: params });
	}
	const scopes = scope.split(" ");
	if (!scopes.includes("openid")) {
		c.failure("Could not find 'openid' in scope http request parameter", { expected: "openid", actual: scopes });
	}
	c.success("Found 'openid' in scope http request parameter", { expected: "openid", actual: scopes });
}

/**
 * The request parameters, request_uri removed, max_age as a number, overridden by the request object's claims
 * (upstream "authorization_request_object") when there is one.
 *
 * upstream: condition/as/CreateEffectiveAuthorizationRequestParameters.java
 */
export function createEffectiveAuthorizationRequestParameters(
	params: AuthorizationParams,
	requestObject: ParsedJwt | null = null,
	...requirements: string[]
): AuthorizationParams {
	const c: Condition = condition("CreateEffectiveAuthorizationRequestParameters", ...requirements);
	const effective = structuredClone(params);
	delete effective["request_uri"];
	for (const name of ["authorization_details", "dcql_query", "client_metadata"]) {
		const value = effective[name];
		if (typeof value === "string") {
			try {
				effective[name] = JSON.parse(value);
			} catch (e) {
				c.failureFrom("Unable to parse " + name + " as JSON", e, { [name]: value });
			}
		}
	}
	// numeric query parameters arrive as strings (EnsureNumericRequestObjectClaimsAreNotNull.numericClaimNames)
	const maxAge = effective["max_age"];
	if (typeof maxAge === "string" && maxAge.trim() !== "" && !Number.isNaN(Number(maxAge))) {
		effective["max_age"] = Number(maxAge);
	}
	// the request object's claims override the request parameters (after the max_age conversion: a request object
	// with max_age as a string is a protocol violation another check reports)
	if (requestObject != null) {
		Object.assign(effective, structuredClone(requestObject.claims));
	}
	c.success("Merged http request parameters with request object claims", {
		effective_authorization_endpoint_request: effective,
	});
	return effective;
}

/** upstream: condition/as/ExtractRequestedScopes.java */
export function extractRequestedScopes(params: AuthorizationParams, ...requirements: string[]): string {
	const c: Condition = condition("ExtractRequestedScopes", ...requirements);
	const scope = param(params, "scope");
	if (!scope) {
		c.failure("Missing scope parameter");
	}
	c.success("Requested scopes", { scope });
	return scope;
}

/** upstream: condition/as/ExtractNonceFromAuthorizationRequest.java */
export function extractNonceFromAuthorizationRequest(params: AuthorizationParams, ...requirements: string[]): string {
	const c: Condition = condition("ExtractNonceFromAuthorizationRequest", ...requirements);
	const nonce = param(params, "nonce");
	if (!nonce) {
		c.failure("Couldn't find 'nonce' in authorization endpoint parameters");
	}
	c.success("Extracted nonce", { nonce });
	return nonce;
}

/** upstream: condition/as/CheckForInvalidCharsInNonce.java */
export function checkForInvalidCharsInNonce(nonce: string, ...requirements: string[]): void {
	const c: Condition = condition("CheckForInvalidCharsInNonce", ...requirements);
	if (!nonce) {
		c.failure("nonce is empty");
	}
	const invalid = [...new Set([...nonce].filter((ch) => !/^[A-Za-z0-9\-_.~]$/.test(ch)))];
	if (invalid.length > 0) {
		c.failure("Non URL safe characters found in nonce. This may introduce interoperability issues.", {
			nonce,
			invalid_chars: invalid,
		});
	}
	c.success("Nonce contains only URL safe characters");
}

/** upstream: condition/as/CheckNonceMaximumLength.java */
export function checkNonceMaximumLength(nonce: string, ...requirements: string[]): void {
	const c: Condition = condition("CheckNonceMaximumLength", ...requirements);
	const max = 43;
	if (!nonce) {
		c.failure("nonce is empty");
	}
	if (nonce.length > max) {
		c.failure(
			`Nonce contains in excess of ${max} characters. To promote interoperability we expect nonces no longer than ${max} characters ` +
				"(the longest the conformance suite generates when testing an authorization server); " +
				"longer values may not be accepted by all wallets/clients.",
			{ nonce, length: nonce.length },
		);
	}
	c.success(
		`Nonce does not exceed ${max} characters (the longest the conformance suite generates when testing an authorization server).`,
		{ nonce, length: nonce.length },
	);
}

/**
 * The extra nonce checks of the success-case module: URL safe characters and at most 43 characters (warnings,
 * skipped without a nonce).
 *
 * upstream: openid/client/OIDCCClientTest.extractNonceFromAuthorizationEndpointRequestParameters
 */
export function checkNonceInteroperability(nonce: string | null): void {
	if (nonce == null) {
		skipped("CheckForInvalidCharsInNonce", { string: "nonce" });
		skipped("CheckNonceMaximumLength", { string: "nonce" });
		return;
	}
	soft(() => checkForInvalidCharsInNonce(nonce), "warning");
	soft(() => checkNonceMaximumLength(nonce), "warning");
}

/** upstream: condition/as/EnsureAuthorizationRequestContainsPkceCodeChallenge.java */
export function ensureAuthorizationRequestContainsPkceCodeChallenge(
	params: AuthorizationParams,
	...requirements: string[]
): { code_challenge: string; code_challenge_method: string } {
	const c: Condition = condition("EnsureAuthorizationRequestContainsPkceCodeChallenge", ...requirements);
	const challenge = param(params, "code_challenge");
	const method = param(params, "code_challenge_method");
	if (!challenge) {
		c.failure("Missing required code_challenge parameter.");
	}
	if (!method) {
		c.failure("Missing required code_challenge_method parameter.");
	}
	if (method !== "S256") {
		c.failure("S256 is required for PKCE.", { code_challenge_method: method });
	}
	c.success("Found required PKCE parameters in request", { code_challenge_method: method, code_challenge: challenge });
	return { code_challenge: challenge, code_challenge_method: method };
}

const ENSURE_RESPONSE_TYPE: Record<string, string> = {
	code: "EnsureResponseTypeIsCode",
	id_token: "EnsureResponseTypeIsIdToken",
	"code id_token": "EnsureResponseTypeIsCodeIdToken",
	"code id_token token": "EnsureResponseTypeIsCodeIdTokenToken",
	"code token": "EnsureResponseTypeIsCodeToken",
	"id_token token": "EnsureResponseTypeIsIdTokenToken",
};

/**
 * The request's response_type is the variant's (in any order).
 *
 * upstream: condition/as/AbstractEnsureResponseType.java, EnsureResponseTypeIsCode.java, EnsureResponseTypeIsIdToken.java,
 * EnsureResponseTypeIsCodeIdToken.java, EnsureResponseTypeIsCodeIdTokenToken.java, EnsureResponseTypeIsCodeToken.java,
 * EnsureResponseTypeIsIdTokenToken.java
 */
export function ensureResponseTypeIs(params: AuthorizationParams, expected: string, ...requirements: string[]): void {
	const c: Condition = condition(ENSURE_RESPONSE_TYPE[expected] ?? "EnsureResponseType", ...requirements);
	const actual = param(params, "response_type");
	if (!actual) {
		c.failure("Could not find response type in request");
	}
	// UPSTREAM: Java's Set.of() throws on duplicate elements (e.g. "code code"); a JS Set silently dedupes
	const got = new Set(actual.split(" "));
	const want = new Set(expected.split(" "));
	if (got.size !== want.size || ![...got].every((t) => want.has(t))) {
		c.failure("Response type is not expected value", { expected, actual });
	}
	c.success("Response type is expected value", { expected });
}

/** upstream: condition/as/EnsureMatchingClientId.java */
export function ensureMatchingClientId(client: RpClient, params: AuthorizationParams, ...requirements: string[]): void {
	const c: Condition = condition("EnsureMatchingClientId", ...requirements);
	const expected = client.client_id;
	const actual = param(params, "client_id");
	if (!expected || expected !== actual) {
		c.failure("Mismatch between Client ID in test configuration and the one in the authorization request", {
			expected: expected ?? "",
			actual: actual ?? "",
		});
	}
	c.success("Client ID matched", { client_id: actual });
}

/**
 * The redirect_uri is one of the client's (https unless a web client uses only code; http only on localhost for
 * native clients). Returns it (upstream "authorization_endpoint_request_redirect_uri").
 *
 * upstream: condition/as/EnsureValidRedirectUriForAuthorizationEndpointRequest.java
 */
export function ensureValidRedirectUriForAuthorizationEndpointRequest(
	client: RpClient,
	params: AuthorizationParams,
	...requirements: string[]
): string {
	const c: Condition = condition("EnsureValidRedirectUriForAuthorizationEndpointRequest", ...requirements);
	const redirectUris = client["redirect_uris"];
	if (redirectUris === undefined) {
		c.failure("redirect_uris is undefined for the client");
	}
	const actual = param(params, "redirect_uri");
	if (actual == null) {
		c.failure("redirect_uri is not present in authorization request", { auth_request: params });
	}
	// UPSTREAM: java.net.URI is replaced by the WHATWG URL parser for the syntax check
	if (!URL.canParse(actual)) {
		c.failure("Invalid redirect_uri", { redirect_uri: actual });
	}
	if (actual.includes("#")) {
		c.failure("Invalid redirect_uri. redirect_uri includes a fragment component.", { redirect_uri: actual });
	}
	if (!Array.isArray(redirectUris)) {
		c.failureFrom("redirect_uris is not an array", new Error("Not a JSON Array: " + JSON.stringify(redirectUris)));
	}
	for (const uri of redirectUris) {
		if (actual !== uri) {
			continue;
		}
		const applicationType = typeof client["application_type"] === "string" ? client["application_type"] : null;
		// https is required if application_type is web and response_type is not code
		if (!requireHttpsIfWebAndResponseTypeNotCode(applicationType, param(params, "response_type"), actual)) {
			c.failure(
				"redirect_uri is one of the registered uris but uses http scheme which is not allowed when application_type is web and response type is not code",
				{ actual, expected: redirectUris },
			);
		}
		let allowed: boolean;
		try {
			allowed = dontAllowHttpIfNativeAndNotLocalhost(applicationType, actual);
		} catch (e) {
			c.failureFrom("Invalid redirect_uri syntax", e, { actual });
		}
		if (!allowed) {
			c.failure(
				"redirect_uri is one of the registered uris but http scheme   is only allowed for localhost for native applications",
				{ actual, expected: redirectUris },
			);
		}
		c.success("redirect_uri is one of the allowed redirect uris", { actual, expected: redirectUris });
		return actual;
	}
	c.failure("redirect_uri is not one of the allowed ones", { actual, expected: redirectUris });
}

/** upstream: condition/as/EnsureOpenIDInScopeRequest.java */
export function ensureOpenIDInScopeRequest(scope: string, ...requirements: string[]): void {
	const c: Condition = condition("EnsureOpenIDInScopeRequest", ...requirements);
	const scopes = scope.split(" ");
	if (!scopes.includes("openid")) {
		// UPSTREAM: the typo is upstream's
		c.failure("Coudln't find 'openid' scope in request", { expected: "openid", actual: scopes });
	}
	c.success("Found 'openid' scope in request", { expected: "openid", actual: scopes });
}

/** The request type an OP under test handles: what the request carries (opUnderTest) */
function requestTypeOf(params: AuthorizationParams): RpVariant["request_type"] {
	if (params["request"] != null) {
		return "request_object";
	}
	if (params["request_uri"] != null) {
		return "request_uri";
	}
	return "plain_http_request";
}

/** The prompt values of the request (upstream reads prompt as one string) */
function promptValues(params: AuthorizationParams): string[] {
	return (param(params, "prompt") ?? "").split(" ").filter(Boolean);
}

/**
 * opUnderTest: the user's auth_time for this authorization: the session's, unless there is none, the request has
 * prompt=login, or the session is older than the requested max_age (then the user authenticates afresh)
 */
function sessionAuthTime(op: EmulatedOp, params: AuthorizationParams): number {
	const now = Math.floor(Date.now() / 1000);
	const previous = op.sessionAuthTime;
	const maxAge = typeof params["max_age"] === "number" ? params["max_age"] : null;
	const fresh =
		previous == null || promptValues(params).includes("login") || (maxAge != null && now - previous > maxAge);
	op.sessionAuthTime = fresh ? now : previous;
	return op.sessionAuthTime as number;
}

/** upstream: condition/as/DisallowMaxAgeEqualsZeroAndPromptNone.java */
export function disallowMaxAgeEqualsZeroAndPromptNone(params: AuthorizationParams, ...requirements: string[]): void {
	const c: Condition = condition("DisallowMaxAgeEqualsZeroAndPromptNone", ...requirements);
	if (params["max_age"] === 0 && param(params, "prompt") === "none") {
		c.failure("Login required. Request contains max_age=0 and prompt=none parameters");
	}
	c.success("The client did not send max_age=0 and prompt=none parameters as expected");
}

/** upstream: condition/as/EnsureScopeContainsAtLeastOneOfProfileEmailPhoneAddress.java */
export function ensureScopeContainsAtLeastOneOfProfileEmailPhoneAddress(
	scope: string,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureScopeContainsAtLeastOneOfProfileEmailPhoneAddress", ...requirements);
	const scopes = scope.split(" ");
	if (!["profile", "email", "phone", "address"].some((s) => scopes.includes(s))) {
		c.failure("Could not find at least one of profile, email, phone and address scope in request", { actual: scopes });
	}
	c.success("Found at least one of profile, email, phone and address scopes in request", { actual: scopes });
}

// ---------------------------------------------------------------------------------------------------------------
// the claims request parameter (OIDCC 5.5)

/** The `claims` parameter as upstream reads it (getAsJsonObject): null when absent, an error when not an object */
function claimsParameter(params: AuthorizationParams): Record<string, unknown> | null {
	const claims = params["claims"];
	if (claims == null) {
		return null;
	}
	if (typeof claims === "string") {
		// DEVIATION: upstream reads the claims query parameter as a JSON object without parsing it (getAsJsonObject
		// throws on the string), so any RP sending one gets a 500; OIDCC 5.5 sends it as a JSON string, so it is parsed
		try {
			const parsed: unknown = JSON.parse(claims);
			if (parsed != null && typeof parsed === "object" && !Array.isArray(parsed)) {
				return parsed as Record<string, unknown>;
			}
		} catch {
			// not JSON: the error below
		}
	}
	if (typeof claims !== "object" || Array.isArray(claims)) {
		throw new Error("Not a JSON Object: " + JSON.stringify(claims));
	}
	return claims as Record<string, unknown>;
}

/** upstream: condition/as/CheckForUnexpectedClaimsInClaimsParameter.java */
export function checkForUnexpectedClaimsInClaimsParameter(
	params: AuthorizationParams,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckForUnexpectedClaimsInClaimsParameter", ...requirements);
	const claims = claimsParameter(params);
	if (claims == null || Object.keys(claims).length === 0) {
		c.success("authorization request 'claims' parameter does not exist or is empty");
		return;
	}
	const unknown = Object.keys(claims).filter((k) => k !== "userinfo" && k !== "id_token");
	if (unknown.length > 0) {
		c.failure("unknown claims found in authorization request 'claims' parameter", {
			claims: Object.keys(claims),
			unknown_claims: unknown,
		});
	}
	c.success("authorization request 'claims' parameter contains only expected claims", { claims: Object.keys(claims) });
}

/** OpenID standard claims (upstream AbstractValidateOpenIdStandardClaims.STANDARD_CLAIMS keys) */
const STANDARD_CLAIMS = new Set([
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
	"email_verified",
	"gender",
	"birthdate",
	"zoneinfo",
	"locale",
	"phone_number",
	"phone_number_verified",
	"address",
	"updated_at",
	"_claim_names",
	"_claim_sources",
	"txn",
]);

/** upstream: condition/as/CheckForUnexpectedOpenIdClaims.java */
export function checkForUnexpectedOpenIdClaims(params: AuthorizationParams, ...requirements: string[]): void {
	const c: Condition = condition("CheckForUnexpectedOpenIdClaims", ...requirements);
	const additions = ["acr", "cpf", "cnpj", "openbanking_intent_id", "verified_claims"];
	const claims = claimsParameter(params);
	if (claims == null || Object.keys(claims).length === 0) {
		c.success("authorization request 'claims' parameter does not exist or is empty");
		return;
	}
	const all: Record<string, string[]> = {};
	const unknown: Record<string, string[]> = {};
	for (const [claim, value] of Object.entries(claims)) {
		if (value == null || typeof value !== "object" || Array.isArray(value)) {
			continue;
		}
		for (const member of Object.keys(value)) {
			(all[claim] ??= []).push(member);
			if (!STANDARD_CLAIMS.has(member) && !additions.includes(member)) {
				(unknown[claim] ??= []).push(member);
			}
		}
	}
	if (Object.keys(unknown).length > 0) {
		c.failure("unknown claims found in authorization request 'claims' parameter member objects", {
			claims: all,
			unknown_claims: unknown,
		});
	}
	c.success("authorization request 'claims' parameter member objects contain only expected claims", { claims: all });
}

/** upstream: condition/as/CheckRequestClaimsParameterValues.java */
export function checkRequestClaimsParameterValues(params: AuthorizationParams, ...requirements: string[]): void {
	const c: Condition = condition("CheckRequestClaimsParameterValues", ...requirements);
	const claims = claimsParameter(params);
	if (claims == null || Object.keys(claims).length === 0) {
		c.success("authorization request 'claims' parameter does not exist or is empty");
		return;
	}
	const valid: string[] = [];
	const invalid: string[] = [];
	for (const [claim, value] of Object.entries(claims)) {
		if (claim !== "userinfo" && claim !== "id_token") {
			continue;
		}
		(value != null && typeof value === "object" && !Array.isArray(value) ? valid : invalid).push(claim);
	}
	if (invalid.length > 0) {
		c.failure("the expected authorization request 'claims' parameter claims values are not json objects", {
			valid_claims: valid,
			invalid_claims: invalid,
		});
	}
	c.success("the expected authorization request 'claims' parameter claims values are json objects", {
		valid_claims: valid,
	});
}

/** Records the path's last element as a claim of the object named by the rest of the path */
function addClaimMember(store: Record<string, string[]>, path: string[]): void {
	const claim = path[path.length - 1];
	const list = (store[path.slice(0, -1).join(".")] ??= []);
	if (!list.includes(claim)) {
		list.push(claim);
	}
}

/** upstream: condition/as/CheckRequestClaimsParameterMemberValues.java */
export function checkRequestClaimsParameterMemberValues(params: AuthorizationParams, ...requirements: string[]): void {
	const c: Condition = condition("CheckRequestClaimsParameterMemberValues", ...requirements);
	const claims = claimsParameter(params);
	if (claims == null || Object.keys(claims).length === 0) {
		c.success("authorization request 'claims' parameter does not exist or is empty");
		return;
	}
	const validValueKeys = ["essential", "value", "values"];
	const validClaimPaths = [
		"userinfo",
		"userinfo.verified_claims.verification",
		"userinfo.verified_claims.claims",
		"id_token",
		"id_token.verified_claims.verification",
		"id_token.verified_claims.claims",
	];
	const all: Record<string, string[]> = {};
	const invalid: Record<string, string[]> = {};
	const check = (object: Record<string, unknown>, path: string[]) => {
		if (Object.keys(object).length === 0) {
			addClaimMember(all, path);
			return;
		}
		for (const [key, value] of Object.entries(object)) {
			const local = [...path];
			if (value != null && typeof value === "object" && !Array.isArray(value)) {
				local.push(key);
				check(value as Record<string, unknown>, local);
				continue;
			}
			if (value === null) {
				local.push(key);
				addClaimMember(all, local);
				continue;
			}
			for (const validPath of validClaimPaths) {
				if (validPath.startsWith(local.join("."))) {
					local.push(key);
				}
			}
			addClaimMember(all, local);
			if (!validValueKeys.includes(key)) {
				addClaimMember(invalid, local);
			}
		}
	};
	for (const [claim, value] of Object.entries(claims)) {
		if (claim !== "userinfo" && claim !== "id_token") {
			continue;
		}
		if (value == null || typeof value !== "object" || Array.isArray(value)) {
			// UPSTREAM: Java getAsJsonObject() throws if the member is not a JSON object
			throw new Error("Not a JSON Object: " + JSON.stringify(value));
		}
		check(value as Record<string, unknown>, [claim]);
	}
	if (Object.keys(invalid).length > 0) {
		c.failure("the authorization request id_token/userinfo claims contain claim members with invalid values", {
			claim_members: all,
			invalid_claims: invalid,
		});
	}
	c.success("the authorization request id_token/userinfo claims contain only claim members with valid values", {
		claim_members: all,
	});
}

// ---------------------------------------------------------------------------------------------------------------
// the response

/** upstream: condition/as/CreateAuthorizationCode.java */
export function createAuthorizationCode(): string {
	const code = randomAlphanumeric(32);
	condition("CreateAuthorizationCode").success("Created authorization code", { authorization_code: code });
	return code;
}

/** upstream: condition/as/CreateAuthorizationEndpointResponseParams.java */
export function createAuthorizationEndpointResponseParams(params: AuthorizationParams): Record<string, string> {
	const response: Record<string, string> = {};
	const redirectUri = param(params, "redirect_uri");
	const state = param(params, "state");
	if (redirectUri != null) {
		response["redirect_uri"] = redirectUri;
	}
	if (state != null) {
		response["state"] = state;
	}
	condition("CreateAuthorizationEndpointResponseParams").success(
		"Added authorization_endpoint_response_params to environment",
		{ params: response },
	);
	return response;
}

/** upstream: condition/as/AddCodeToAuthorizationEndpointResponseParams.java */
export function addCodeToAuthorizationEndpointResponseParams(
	response: Record<string, string>,
	code: string,
	...requirements: string[]
): void {
	response["code"] = code;
	condition("AddCodeToAuthorizationEndpointResponseParams", ...requirements).success(
		"Added code to authorization endpoint response params",
		{ authorization_endpoint_response_params: response },
	);
}

/** upstream: condition/as/AddIdTokenToAuthorizationEndpointResponseParams.java */
export function addIdTokenToAuthorizationEndpointResponseParams(
	response: Record<string, string>,
	idToken: string,
	...requirements: string[]
): void {
	response["id_token"] = idToken;
	condition("AddIdTokenToAuthorizationEndpointResponseParams", ...requirements).success(
		"Added id_token to authorization endpoint response params",
		{ authorization_endpoint_response_params: response },
	);
}

/** upstream: condition/as/AddTokenToAuthorizationEndpointResponseParams.java */
export function addTokenToAuthorizationEndpointResponseParams(
	response: Record<string, string>,
	accessToken: string,
	tokenType: string,
	...requirements: string[]
): void {
	response["access_token"] = accessToken;
	response["token_type"] = tokenType;
	condition("AddTokenToAuthorizationEndpointResponseParams", ...requirements).log(
		"Added token and token_type to authorization endpoint response params",
		{ authorization_endpoint_response_params: response },
	);
}

/** upstream: condition/as/SendAuthorizationResponseWithResponseModeQuery.java */
export function sendAuthorizationResponseWithResponseModeQuery(
	response: Record<string, string>,
	...requirements: string[]
): string {
	const { redirect_uri: redirectUri, ...params } = response;
	const redirectTo = toUriString(redirectUri, Object.entries(params));
	condition("SendAuthorizationResponseWithResponseModeQuery", ...requirements).log("Redirecting back to client", {
		uri: redirectTo,
	});
	return redirectTo;
}

/** upstream: condition/as/SendAuthorizationResponseWithResponseModeFragment.java */
export function sendAuthorizationResponseWithResponseModeFragment(
	response: Record<string, string>,
	...requirements: string[]
): string {
	const { redirect_uri: redirectUri, ...params } = response;
	const fragment = Object.entries(params)
		.map(([k, v]) => encodeQueryParam(k) + "=" + encodeQueryParam(v))
		.join("&");
	const redirectTo = redirectUri + "#" + fragment;
	condition("SendAuthorizationResponseWithResponseModeFragment", ...requirements).log("Redirecting back to client", {
		uri: redirectTo,
	});
	return redirectTo;
}

/** The page that posts the response to the RP (upstream templates/formPostResponseMode.html) */
export function formPostResponsePage(response: Record<string, string>): Response {
	const { redirect_uri: action, ...params } = response;
	const inputs = Object.entries(params)
		.map(([k, v]) => `<div><input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}"></div>`)
		.join("\n");
	return htmlResponse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OIDF Conformance: form_post submission page</title>
<meta http-equiv="Cache-control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
</head>
<body onload="document.forms[0].submit()">
<div><form action="${escapeHtml(action)}" method="post" enctype="application/x-www-form-urlencoded">
${inputs}
<input type="submit" value="Click to submit the form manually">
</form></div>
<footer><div>OpenID Foundation conformance suite (TypeScript port)</div></footer>
</body>
</html>`);
}

// ---------------------------------------------------------------------------------------------------------------
// the endpoint

/**
 * The RP's authorization request (GET query or POST form): the request is checked (a failing check ends the test,
 * as upstream), the module's extra checks run (`checkNonce`, `checkAuthorizationRequest`), then the OP answers
 * with the variant's response_type and response_mode.
 *
 * upstream: AbstractOIDCCClientTest.handleAuthorizationEndpointRequest (extractAuthorizationEndpointRequestParameters,
 * validateAuthorizationEndpointRequestParameters, createAuthorizationCode, generateAccessToken, createIdToken,
 * redirectFromAuthorizationEndpoint / generateFormPostResponse)
 */
export async function handleAuthorizationRequest(
	op: EmulatedOp,
	req: IncomingRequest,
): Promise<{ response: Response; authorization: AuthorizationState; responseParams: Record<string, string> }> {
	return block(op.options.authorizationBlock?.(op) ?? "Authorization endpoint", async () => {
		let httpParams: AuthorizationParams;
		if (req.method === "POST") {
			httpParams = req.body_form_params ?? {};
		} else if (req.method === "GET") {
			httpParams = req.query_string_params;
		} else {
			throw new Error("Got unexpected HTTP method to authorization endpoint");
		}

		if (op.options.opUnderTest) {
			op.selectClient({ clientId: typeof httpParams["client_id"] === "string" ? httpParams["client_id"] : null });
		}
		// extractAuthorizationEndpointRequestParameters
		let requestObject: ParsedJwt | null = null;
		// an OP under test takes whatever the request carries; the RP test's OP expects the variant's request type
		const requestType = op.options.opUnderTest ? requestTypeOf(httpParams) : op.variant.request_type;
		if (requestType === "plain_http_request") {
			ensureRequestDoesNotContainRequestObject(httpParams, "OIDCC-6.1");
		} else {
			requestObject = await extractRequestObjectFromAuthorizationRequest(op, httpParams, requestType);
		}
		ensureAuthorizationHttpRequestContainsOpenIDScope(httpParams, "OIDCC-6.1", "OIDCC-6.2");
		if (requestObject != null) {
			await checkRequestObject(op, httpParams, requestObject);
		}
		const params = createEffectiveAuthorizationRequestParameters(httpParams, requestObject, "OIDCC-6.1", "OIDCC-6.2");
		const scope = extractRequestedScopes(params);
		const nonce = param(params, "response_type")?.includes("id_token")
			? extractNonceFromAuthorizationRequest(params, "OIDCC-3.1.2.1", "OIDCC-3.2.2.1")
			: (soft(() => extractNonceFromAuthorizationRequest(params, "OIDCC-3.1.2.1"), "info") ?? null);
		op.options.checkNonce?.(nonce);
		let codeChallenge: AuthorizationState["codeChallenge"] = null;
		if (params["code_challenge"] == null) {
			skipped(
				"EnsureAuthorizationRequestContainsPkceCodeChallenge",
				{ element: ["effective_authorization_endpoint_request", "code_challenge"] },
				"RFC7636-4.3",
			);
		} else {
			codeChallenge = ensureAuthorizationRequestContainsPkceCodeChallenge(params, "RFC7636-4.3");
		}

		// validateAuthorizationEndpointRequestParameters
		if (op.options.checkResponseType) {
			op.options.checkResponseType(params);
		} else {
			ensureResponseTypeIs(params, op.variant.response_type);
		}
		const client = op.client;
		if (client == null) {
			throw new Error("The RP sent an authorization request before it registered a client");
		}
		ensureMatchingClientId(client, params, "OIDCC-3.1.2.1");
		const redirectUri = ensureValidRedirectUriForAuthorizationEndpointRequest(client, params, "OIDCC-3.1.2.1");
		ensureOpenIDInScopeRequest(scope, "OIDCC-3.1.2.1");
		if (op.options.allowMaxAgeZeroWithPromptNone !== true) {
			disallowMaxAgeEqualsZeroAndPromptNone(params, "OIDCC-3.1.2.3");
		}
		op.options.checkAuthorizationRequest?.(params, scope);

		const unexpectedClaimsRequirements = [
			"RFC6749-4.1.1",
			"OIDCC-3.1.2.1",
			"RFC7636-4.3",
			"OAuth2-RT-2.1",
			"RFC7519-4.1",
			"DPOP-10",
			"RFC8485-4.1",
			"RFC8707-2.1",
			"RFC9396-2",
		];
		if (requestObject == null) {
			// only request objects carry claims of their own
			skipped(
				"CheckForUnexpectedClaimsInRequestObject",
				{ element: ["authorization_request_object", "claims"] },
				...unexpectedClaimsRequirements,
			);
		} else {
			const ro = requestObject;
			soft(() => checkForUnexpectedClaimsInRequestObject(ro, ...unexpectedClaimsRequirements), "warning");
		}
		const claimsChecks: [string, (p: AuthorizationParams, ...r: string[]) => void, "warning" | "failure", string[]][] =
			[
				[
					"CheckForUnexpectedClaimsInClaimsParameter",
					checkForUnexpectedClaimsInClaimsParameter,
					"warning",
					["OIDCC-5.5"],
				],
				[
					"CheckForUnexpectedOpenIdClaims",
					checkForUnexpectedOpenIdClaims,
					"warning",
					["OIDCC-5.1", "OIDCC-5.5.1.1", "BrazilOB-5.2.2.3", "BrazilOB-5.2.2.4", "OBSP-3.4"],
				],
				["CheckRequestClaimsParameterValues", checkRequestClaimsParameterValues, "failure", ["OIDCC-5.5"]],
				[
					"CheckRequestClaimsParameterMemberValues",
					checkRequestClaimsParameterMemberValues,
					"failure",
					["OIDCC-5.5.1"],
				],
			];
		for (const [name, check, severity, requirements] of claimsChecks) {
			if (params["claims"] == null) {
				skipped(name, { element: ["effective_authorization_endpoint_request", "claims"] }, ...requirements);
			} else {
				soft(() => check(params, ...requirements), severity);
			}
		}

		if (op.options.opUnderTest && op.sessionAuthTime == null && promptValues(params).includes("none")) {
			throw new OAuthError("login_required", "The user is not logged in and the request has prompt=none");
		}
		const authorization: AuthorizationState = {
			params,
			scope,
			nonce,
			redirectUri,
			code: null,
			cHash: null,
			codeChallenge,
			// an OP under test has a session; upstream sets auth_time once the response is sent (below)
			authTime: op.options.opUnderTest ? sessionAuthTime(op, params) : null,
		};
		op.authorization = authorization;
		if (op.responseType.includesCode) {
			authorization.code = createAuthorizationCode();
			// c_hash won't work when id_token_signed_response_alg is none
			if (op.signingAlg !== "none") {
				authorization.cHash = calculateCHash(authorization.code, op.signingAlg as string, "OIDCC-3.3.2.11");
			}
		}
		if (op.responseType.includesToken) {
			generateAccessToken(op);
		}
		const idToken = op.responseType.includesIdToken ? await createIdToken(op, false) : null;

		const responseParams = createAuthorizationEndpointResponseParams(params);
		if (authorization.code != null) {
			addCodeToAuthorizationEndpointResponseParams(responseParams, authorization.code, "OIDCC-3.3.2.5");
		}
		if (idToken != null) {
			addIdTokenToAuthorizationEndpointResponseParams(responseParams, idToken, "OIDCC-3.3.2.5");
		}
		if (op.responseType.includesToken && op.tokens != null) {
			addTokenToAuthorizationEndpointResponseParams(
				responseParams,
				op.tokens.accessToken,
				op.tokens.tokenType,
				"OIDCC-3.3.2.5",
			);
		}
		op.options.customizeAuthorizationResponse?.(responseParams);

		let response: Response;
		if (op.variant.response_mode === "form_post") {
			response = formPostResponsePage(responseParams);
		} else {
			const redirectTo =
				op.responseType.includesIdToken || op.responseType.includesToken
					? sendAuthorizationResponseWithResponseModeFragment(responseParams, "OIDCC-3.3.2.5")
					: sendAuthorizationResponseWithResponseModeQuery(responseParams, "OIDCC-3.3.2.5");
			response = new Response(null, { status: 302, headers: { location: redirectTo } });
		}
		authorization.authTime ??= Math.floor(Date.now() / 1000);
		return { response, authorization, responseParams };
	});
}

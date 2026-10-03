/**
 * The userinfo endpoint, the protected resource the OP tests call with the access token.
 *
 *   const url = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
 *   const res = await userinfo.callProtectedResource(url, tokens.accessToken);
 *   soft(() => ensureHttpStatusCodeIs200(res));
 */
import { condition, soft, type Condition } from "../suite/conditions.ts";
import { endpointResponse, HttpError, request, type EndpointResponse } from "../suite/http.ts";
import type { ParsedJwt } from "../suite/jose.ts";
import type { AuthorizationRequest } from "./authorization.ts";
import {
	objectValidator,
	SCOPE_STANDARD_CLAIMS,
	VALIDATE_BIRTHDATE,
	VALIDATE_BOOLEAN,
	VALIDATE_JSON_OBJECT,
	VALIDATE_NUMBER,
	VALIDATE_STRING,
	type ElementValidator,
} from "./id-token.ts";
import type { Op } from "./op.ts";
import type { AccessToken } from "./token.ts";

/**
 * Calls `url` with the access token (Authorization: <token type> <token>); any status is a response.
 *
 * upstream: condition/client/CallProtectedResource.java (AbstractCallProtectedResourceWithBearerToken)
 */
export async function callProtectedResource(
	url: string,
	accessToken: AccessToken,
	opts: { method?: "GET" | "POST"; headers?: Record<string, string>; body?: string | URLSearchParams } = {},
): Promise<EndpointResponse> {
	const c: Condition = condition("CallProtectedResource");
	if (!accessToken.value) {
		c.failure("Access token not found");
	}
	const type = accessToken.type;
	if (!type) {
		c.failure("Token type not found");
	}
	if (type.toLowerCase() !== "bearer" && type.toLowerCase() !== "dpop") {
		c.failure("Access token is neither a bearer nor a dpop token", { token_type: type });
	}
	if (!url) {
		c.failure("Missing Resource URL");
	}
	const method = opts.method ?? "GET";
	const headers: Record<string, string> = { Authorization: type + " " + accessToken.value, ...opts.headers };
	if (!Object.keys(headers).some((h) => h.toLowerCase() === "accept")) {
		headers["accept"] = "application/json";
	}
	if (method === "POST" && !Object.keys(headers).some((h) => h.toLowerCase() === "content-type")) {
		// https://bitbucket.org/openid/connect/issues/1137/is-content-type-application-x-www-form
		headers["content-type"] = "application/x-www-form-urlencoded";
	}
	let res;
	try {
		res = await request(c.name, { url, method, headers, body: opts.body ?? null });
	} catch (e) {
		if (e instanceof HttpError) {
			const cause = e.cause instanceof Error ? e.cause.message : null;
			c.failureFrom("Call to protected resource " + url + " failed" + (cause ? " - " + cause : ""), e);
		}
		throw e;
	}
	const response = endpointResponse("resource", res);
	const { body_json: _json, ...logged } = response;
	c.success("Got a response from the resource endpoint", logged);
	return response;
}

/** The userinfo response (upstream env "userinfo": the parsed body of "userinfo_endpoint_response_full") */
export type UserInfo = Record<string, unknown>;

/**
 * Calls the userinfo endpoint (`server.userinfo_endpoint`, not the protected resource url) with the access token;
 * any HTTP status is a response. `conditionName` is the upstream condition the call is logged under
 * (CallUserInfoEndpoint, CallUserInfoEndpointWithBearerTokenInBody).
 *
 * upstream: condition/client/CallUserInfoEndpoint.java (AbstractCallProtectedResourceWithBearerToken)
 */
export async function callUserInfoEndpoint(
	op: Pick<Op, "metadata">,
	accessToken: AccessToken,
	opts: { conditionName?: string; method?: "GET" | "POST"; tokenInBody?: boolean } = {},
	...requirements: string[]
): Promise<EndpointResponse> {
	const c: Condition = condition(opts.conditionName ?? "CallUserInfoEndpoint", ...requirements);
	const url = op.metadata.userinfo_endpoint;
	if (!url) {
		c.failure('"userinfo_endpoint" missing from server configuration');
	}
	const method = opts.method ?? "GET";
	const headers: Record<string, string> = {};
	let body: URLSearchParams | null = null;
	if (opts.tokenInBody) {
		// CallUserInfoEndpointWithBearerTokenInBody: no Authorization header (AbstractCallProtectedResource.getAccessToken)
		if (!accessToken.value) {
			c.failure("Access token not found");
		}
		if (!accessToken.type) {
			c.failure("Token type not found");
		}
		if (accessToken.type.toLowerCase() !== "bearer") {
			c.failure("Access token is not a bearer token", { token_type: accessToken.type });
		}
		body = new URLSearchParams({ access_token: accessToken.value });
	} else {
		if (!accessToken.value) {
			c.failure("Access token not found");
		}
		const type = accessToken.type;
		if (!type) {
			c.failure("Token type not found");
		}
		if (type.toLowerCase() !== "bearer" && type.toLowerCase() !== "dpop") {
			c.failure("Access token is neither a bearer nor a dpop token", { token_type: type });
		}
		headers["Authorization"] = type + " " + accessToken.value;
	}
	headers["accept"] = "application/json";
	if (method === "POST") {
		// https://bitbucket.org/openid/connect/issues/1137/is-content-type-application-x-www-form
		headers["content-type"] = "application/x-www-form-urlencoded";
	}
	let res;
	try {
		res = await request(c.name, { url, method, headers, body });
	} catch (e) {
		if (e instanceof HttpError) {
			const cause = e.cause instanceof Error ? e.cause.message : null;
			c.failureFrom("Call to protected resource " + url + " failed" + (cause ? " - " + cause : ""), e);
		}
		throw e;
	}
	const response = endpointResponse("resource", res);
	c.success("Got a response from the userinfo endpoint", {
		body: response.body,
		headers: response.headers,
		status_code: { code: response.status },
	});
	return response;
}

/** upstream: condition/client/CallUserInfoEndpointWithBearerTokenInBody.java */
export function callUserInfoEndpointWithBearerTokenInBody(
	op: Pick<Op, "metadata">,
	accessToken: AccessToken,
	...requirements: string[]
): Promise<EndpointResponse> {
	return callUserInfoEndpoint(
		op,
		accessToken,
		{ conditionName: "CallUserInfoEndpointWithBearerTokenInBody", method: "POST", tokenInBody: true },
		...requirements,
	);
}

/** upstream: condition/client/SetResourceMethodToPost.java (the method CallUserInfoEndpoint then uses) */
export function setResourceMethodToPost(): "POST" {
	condition("SetResourceMethodToPost").success("Set protected resource access method to POST");
	return "POST";
}

/** upstream: condition/client/UserInfoEndpointWithAccessTokenInBodyNotSupported.java */
export function userInfoEndpointWithAccessTokenInBodyNotSupported(): never {
	const c: Condition = condition("UserInfoEndpointWithAccessTokenInBodyNotSupported");
	return c.failure(
		"The server returned a non-2xx HTTP response, and hence does not appear to support access tokens passed in the POST body.",
	);
}

/** upstream: condition/client/ExtractUserInfoFromUserInfoEndpointResponse.java */
export function extractUserInfoFromUserInfoEndpointResponse(res: EndpointResponse): UserInfo {
	const c: Condition = condition("ExtractUserInfoFromUserInfoEndpointResponse");
	let parsed: unknown;
	try {
		parsed = JSON.parse(res.body as string);
	} catch (e) {
		c.failureFrom("UserInfo endpoint response is not JSON", e);
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		c.failureFrom(
			"UserInfo endpoint response is not a JSON object",
			new Error("Not a JSON Object: " + JSON.stringify(parsed)),
		);
	}
	const userinfo = parsed as UserInfo;
	c.success("Extracted user info", { userinfo });
	return userinfo;
}

/** upstream: condition/client/ValidateUserInfoStandardClaims.java (AbstractValidateOpenIdStandardClaims) */
export function validateUserInfoStandardClaims(userinfo: UserInfo, ...requirements: string[]): Record<string, unknown> {
	const c: Condition = condition("ValidateUserInfoStandardClaims", ...requirements);
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
	if (!objectValidator(c, null, standard, unknown).isValid(userinfo)) {
		c.failure("Userinfo is not valid");
	}
	c.success("Userinfo is valid");
	return unknown;
}

/** upstream: condition/client/EnsureUserInfoContainsSub.java */
export function ensureUserInfoContainsSub(userinfo: UserInfo, ...requirements: string[]): void {
	const c: Condition = condition("EnsureUserInfoContainsSub", ...requirements);
	const sub = userinfo["sub"];
	if (typeof sub !== "string" || sub === "") {
		c.failure("sub not found in userinfo");
	}
	c.success("Found sub in userinfo", { sub });
}

/** upstream: condition/client/EnsureUserInfoUpdatedAtValid.java (AbstractUpdatedAtValid) */
export function ensureUserInfoUpdatedAtValid(userinfo: UserInfo, ...requirements: string[]): void {
	const c: Condition = condition("EnsureUserInfoUpdatedAtValid", ...requirements);
	const updatedAt = userinfo["updated_at"];
	if (typeof updatedAt !== "number") {
		c.log("userinfo response does not contain 'updated_at'");
		return;
	}
	const now = Date.now();
	const fields = { updated_at: new Date(updatedAt * 1000), now: new Date(now) };
	// 5 minute allowable skew for testing
	if (now + 5 * 60 * 1000 < updatedAt * 1000) {
		c.failure("updated_at in userinfo appears to be in the future", fields);
	}
	// a relatively arbitrary choice, but if the updated_at data is prior to 1990 then it seems impossible that it's
	// valid as it would predate 'the web'
	if (Date.UTC(1990, 0, 1) > updatedAt * 1000) {
		c.failure("updated_at in userinfo appears to be prior to the year 1990", fields);
	}
	c.success("'updated_at' in userinfo response seems to be a valid time", fields);
}

// Java: getAsJsonObject() / getString() throw when the elements are not an object / strings
function asJsonObject(v: unknown): Record<string, unknown> {
	if (typeof v !== "object" || v === null || Array.isArray(v)) {
		throw new Error("Not a JSON Object: " + JSON.stringify(v));
	}
	return v as Record<string, unknown>;
}

/** upstream: condition/client/EnsureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources.java */
export function ensureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources(
	userinfo: UserInfo,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources", ...requirements);
	const claimNames = userinfo["_claim_names"];
	const claimSources = userinfo["_claim_sources"];
	if (claimNames == null && claimSources == null) {
		c.log("userinfo response does not contain '_claim_names' nor _claim_sources'");
		return;
	}
	if (claimNames == null) {
		c.failure("userinfo response contains '_claim_sources' but not _claim_names'");
	}
	if (claimSources == null) {
		c.failure("userinfo response contains '_claim_names' but not _claim_sources'");
	}
	const referenced = new Set(Object.values(asJsonObject(claimNames)).map((v) => String(v)));
	for (const source of Object.keys(asJsonObject(claimSources))) {
		if (!referenced.has(source)) {
			c.failure(
				"Member name '" +
					source +
					"' in userinfo response '_claim_sources' is not referenced by member values in '_claim_names'",
				{ _claim_names: claimNames, _claim_sources: claimSources },
			);
		}
	}
	c.success(
		"userinfo response member names in '_claim_sources' are all referenced by member values in '_claim_names'",
		{
			_claim_names: claimNames,
			_claim_sources: claimSources,
		},
	);
}

/**
 * The checks upstream's AbstractOIDCCUserInfoTest.validateExtractedUserInfoResponse runs for a code flow (the checks
 * for an id_token from the authorization endpoint only apply to the other response types).
 */
export function validateExtractedUserInfoResponse(userinfo: UserInfo): void {
	soft(() => validateUserInfoStandardClaims(userinfo, "OIDCC-5.1"));
	soft(() => ensureUserInfoContainsSub(userinfo, "OIDCC-5.3.2"));
	soft(() => ensureUserInfoUpdatedAtValid(userinfo, "OIDCC-5.1"));
	soft(() => ensureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources(userinfo, "OIDCC-5.6.2"));
}

/** upstream: condition/client/VerifyUserInfoAndIdTokenInTokenEndpointSameSub.java (AbstractVerifyUserInfoAndIdTokenSameSub) */
export function verifyUserInfoAndIdTokenInTokenEndpointSameSub(
	userinfo: UserInfo,
	tokenEndpointIdToken: ParsedJwt,
	...requirements: string[]
): void {
	const c: Condition = condition("VerifyUserInfoAndIdTokenInTokenEndpointSameSub", ...requirements);
	const subUserInfo = userinfo["sub"];
	const subIdToken = tokenEndpointIdToken.claims["sub"];
	if (typeof subUserInfo !== "string" || subUserInfo === "") {
		c.failure('"sub" not found in UserInfo response ');
	}
	if (typeof subIdToken !== "string" || subIdToken === "") {
		c.failure('"sub" not found in token_endpoint_id_token');
	}
	if (subUserInfo !== subIdToken) {
		c.failure('"sub" in user info response doesn\'t match with "sub" in token_endpoint_id_token', {
			sub_user_info: subUserInfo,
			sub_id_token: subIdToken,
		});
	}
	c.success("userinfo response and id_token sub are the same", {
		sub_user_info: subUserInfo,
		sub_id_token: subIdToken,
	});
}

/**
 * The scopes of the authorization request were honoured: the userinfo contains the standard claims of every scope.
 *
 * upstream: condition/client/VerifyScopesReturnedInUserInfoClaims.java (AbstractVerifyScopesReturnedInClaims)
 */
export function verifyScopesReturnedInUserInfoClaims(
	userinfo: UserInfo,
	authorizationRequest: Pick<AuthorizationRequest, "params">,
	...requirements: string[]
): void {
	const c: Condition = condition("VerifyScopesReturnedInUserInfoClaims", ...requirements);
	const scope = authorizationRequest.params["scope"];
	if (typeof scope !== "string" || scope === "") {
		c.failure("'scope' not found in authorization endpoint request");
	}
	const claimsSet = Object.keys(userinfo);
	const expectedScopeItems: string[] = [];
	for (const s of scope.split(" ")) {
		const items = SCOPE_STANDARD_CLAIMS.get(s);
		// UPSTREAM: an unknown scope makes Java throw a NullPointerException (addAll(null)); here a TypeError
		expectedScopeItems.push(...(items as string[]));
	}
	const missing = [...new Set(expectedScopeItems)].filter((item) => !claimsSet.includes(item));
	if (missing.length > 0) {
		c.failure(
			"'claims' in userinfo doesn't contain all scope items of scope in authorization request(corresponds to scope standard claims)",
			{ actual_scope_items: claimsSet, expected_scope_items: expectedScopeItems, missing_items: missing },
		);
	}
	c.success(
		"'claims' in userinfo contains all scope items of scope in authorization request (corresponds to scope standard claims)",
		{ actual_scope_items: claimsSet, expected_scope_items: expectedScopeItems },
	);
}

/** upstream: condition/client/EnsureUserInfoContainsName.java */
export function ensureUserInfoContainsName(userinfo: UserInfo, ...requirements: string[]): void {
	const c: Condition = condition("EnsureUserInfoContainsName", ...requirements);
	const name = userinfo["name"];
	if (typeof name !== "string" || name === "") {
		c.failure("name not found in userinfo");
	}
	c.success("Found name in userinfo", { name });
}

/** upstream: condition/client/EnsureUserInfoDoesNotContainName.java */
export function ensureUserInfoDoesNotContainName(userinfo: UserInfo, ...requirements: string[]): void {
	const c: Condition = condition("EnsureUserInfoDoesNotContainName", ...requirements);
	const name = userinfo["name"];
	if (typeof name === "string") {
		// see discussion on certification email list, 10th March 2020
		c.failure(
			"Unexpectedly found name in userinfo response. The conformance suite did not request the 'name' claim is returned and hence did not expect the server to include it. Technically this does not violate the specifications but it is likely a bug in the server and may result in user data being exposed in unintended ways.",
			{ name },
		);
	}
	c.success(
		"name claim not found in userinfo response, which is expected as it was not requested to be returned there",
	);
}

/**
 * The checks on the userinfo response of the modules that request particular claims, for a code flow: the generic
 * ones, the same sub as in the token endpoint's id_token, and the scopes' claims being returned (warning).
 *
 * upstream: AbstractOIDCCReturnedClaimsServerTest.validateUserInfoResponse
 */
export function validateReturnedClaimsUserInfoResponse(
	userinfo: UserInfo,
	tokenEndpointIdToken: ParsedJwt,
	authorizationRequest: Pick<AuthorizationRequest, "params">,
): void {
	validateExtractedUserInfoResponse(userinfo);
	soft(() => verifyUserInfoAndIdTokenInTokenEndpointSameSub(userinfo, tokenEndpointIdToken, "OIDCC-5.3.2"));
	soft(() => verifyScopesReturnedInUserInfoClaims(userinfo, authorizationRequest, "OIDCC-5.4"), "warning");
}

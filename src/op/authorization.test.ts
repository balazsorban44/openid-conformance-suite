import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	addAllSupportedStandardClaimsToAuthorizationEndpointRequestIdTokenAndUserinfoClaims,
	addIdTokenEssentialNameClaimToAuthorizationEndpointRequest,
	addRandomLocationClaimsToAuthorizationEndpointRequest,
	checkErrorFromAuthorizationEndpointErrorInvalidRequest,
	checkIfOidcStandardClaimsSupported,
	detectWhetherErrorResponseIsInQueryOrFragment,
	ensureUnsupportedResponseTypeOrInvalidRequestError,
	expectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest,
	extractAccessTokenFromAuthorizationResponse,
	extractIdTokenFromAuthorizationResponse,
	validateIdTokenFromAuthorizationResponseEncryption,
	type AuthorizationResponse,
} from "./authorization.ts";
import type { RegisteredClient } from "./registration.ts";

const t = useTestLog();
const last = () => t.entries().at(-1);
/** An authorization response with `params` in the URL fragment (implicit / hybrid) */
const fragmentResponse = (params: Record<string, string>): AuthorizationResponse => ({
	params,
	query: {},
	fragment: params,
	method: "GET",
	headers: {},
});
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const client: RegisteredClient = { client: { client_id: "c1" }, keys: null, dynamic: true };

describe("what the authorization endpoint returns for implicit and hybrid response types", () => {
	test("the access token and its type come from authorization_endpoint_response", () => {
		const token = extractAccessTokenFromAuthorizationResponse(
			fragmentResponse({ access_token: "at-1", token_type: "Bearer" }),
		);
		expect(token).toEqual({ value: "at-1", type: "Bearer" });
		expect(last()).toMatchObject({
			src: "ExtractAccessTokenFromAuthorizationResponse",
			result: "SUCCESS",
			msg: "Extracted the access token",
			value: "at-1",
			type: "Bearer",
		});
		expect(() => extractAccessTokenFromAuthorizationResponse(fragmentResponse({ access_token: "at-1" }))).toThrow(
			ConditionFailed,
		);
		expect(last()).toMatchObject({ msg: "Couldn't find token type in authorization_endpoint_response" });
	});

	test("the id_token is parsed from authorization_endpoint_response", async () => {
		const jwt = `${b64({ alg: "RS256", kid: "k1" })}.${b64({ sub: "a", nonce: "n" })}.c2ln`;
		const parsed = await extractIdTokenFromAuthorizationResponse(fragmentResponse({ id_token: jwt }), client);
		expect(parsed.claims).toEqual({ sub: "a", nonce: "n" });
		expect(last()).toMatchObject({
			src: "ExtractIdTokenFromAuthorizationResponse",
			result: "SUCCESS",
			msg: "Found and parsed the id_token from authorization_endpoint_response",
		});
		await expect(extractIdTokenFromAuthorizationResponse(fragmentResponse({}), client)).rejects.toThrow(
			ConditionFailed,
		);
		expect(last()).toMatchObject({
			result: "FAILURE",
			msg: "Couldn't find id_token in authorization_endpoint_response",
		});
	});

	test("an id_token that is not encrypted needs no client key", () => {
		const jwt = `${b64({ alg: "RS256" })}.${b64({ sub: "a" })}.c2ln`;
		validateIdTokenFromAuthorizationResponseEncryption(fragmentResponse({ id_token: jwt }), { keys: [] }, "OIDCC-10.2");
		expect(last()).toMatchObject({
			src: "ValidateIdTokenFromAuthorizationResponseEncryption",
			result: "SUCCESS",
			msg: "The id_token is not encrypted using an asymmetric encryption algorithm",
			requirements: ["OIDCC-10.2"],
		});
	});
});

describe("a request without nonce for a response type with an id_token", () => {
	test("the expected error is invalid_request", () => {
		checkErrorFromAuthorizationEndpointErrorInvalidRequest(fragmentResponse({ error: "invalid_request" }));
		expect(last()).toMatchObject({
			src: "CheckErrorFromAuthorizationEndpointErrorInvalidRequest",
			result: "SUCCESS",
			expected: ["invalid_request"],
			actual: "invalid_request",
		});
		expect(() =>
			checkErrorFromAuthorizationEndpointErrorInvalidRequest(fragmentResponse({ error: "access_denied" })),
		).toThrow(ConditionFailed);
		expect(last()).toMatchObject({ msg: "'error' field has unexpected value", actual: "access_denied" });
	});
});

describe("claims request parameter", () => {
	test("response_type=id_token asks for the essential name claim in the id_token", () => {
		const params: Record<string, unknown> = { scope: "openid" };
		addIdTokenEssentialNameClaimToAuthorizationEndpointRequest(params, "OIDCC-5.5");
		expect(params["claims"]).toEqual({ id_token: { name: { essential: true } } });
		expect(last()).toMatchObject({
			src: "AddIdTokenEssentialNameClaimToAuthorizationEndpointRequest",
			msg: "Added name claim to authorization_endpoint_request",
		});
	});

	test("CheckIfOidcStandardClaimsSupported: whether claims_supported lists a standard claim", () => {
		expect(checkIfOidcStandardClaimsSupported({ issuer: "i" }, "OIDCC-5.1")).toBe(false);
		expect(last()).toMatchObject({ msg: "claims_supported not found in server metadata" });
		expect(checkIfOidcStandardClaimsSupported({ issuer: "i", claims_supported: ["acr", "custom"] })).toBe(false);
		expect(last()).toMatchObject({
			msg: "claims_supported in server metadata does not contain any of the OpenID Connect standard claims",
		});
		expect(checkIfOidcStandardClaimsSupported({ issuer: "i", claims_supported: ["acr", "email", "sub"] })).toBe(true);
		expect(last()).toMatchObject({
			msg: "claims_supported in server metadata contains at least one OpenID Connect standard claims",
			standard_claims: expect.arrayContaining(["email", "sub"]),
		});
		expect(() => checkIfOidcStandardClaimsSupported({ issuer: "i", claims_supported: "email" })).toThrow(
			"claims_supported in server metadata is not an array",
		);
	});

	test("AddAllSupportedStandardClaims...: the standard claims of claims_supported in every request form", () => {
		const params: Record<string, unknown> = { scope: "openid" };
		addAllSupportedStandardClaimsToAuthorizationEndpointRequestIdTokenAndUserinfoClaims(
			params,
			{ issuer: "i", claims_supported: ["sub", "acr", "name", "email", "birthdate", "phone_number", "address"] },
			"OIDCC-5.5",
		);
		const claims = params["claims"] as Record<string, Record<string, unknown>>;
		for (const location of ["id_token", "userinfo"]) {
			const requested = claims[location];
			expect(Object.keys(requested)).toEqual(["sub", "name", "email", "birthdate", "phone_number", "address"]);
			expect(requested["sub"]).toBeNull();
			expect(requested["name"]).toEqual({});
			expect(requested["email"]).toEqual({ essential: true });
			expect(Object.values(requested["birthdate"] as Record<string, string>)).toHaveLength(1);
			expect(requested["phone_number"]).toEqual({ essential: false });
			expect(requested["address"]).toBeNull();
		}
		expect(last()).toMatchObject({
			src: "AddAllSupportedStandardClaimsToAuthorizationEndpointRequestIdTokenAndUserinfoClaims",
			result: "SUCCESS",
			non_oidc_claims: ["acr"],
		});
		expect(() =>
			addAllSupportedStandardClaimsToAuthorizationEndpointRequestIdTokenAndUserinfoClaims(
				{},
				{ issuer: "i", claims_supported: ["acr"] },
			),
		).toThrow("Server does not seem to support any standard OpenID Connect claims.");
	});

	test("AddRandomLocationClaimsToAuthorizationEndpointRequest: a random claim in a random location", () => {
		const params: Record<string, unknown> = { claims: { id_token: { name: null } } };
		addRandomLocationClaimsToAuthorizationEndpointRequest(params, "OIDCC-5.5");
		const claims = params["claims"] as Record<string, Record<string, unknown>>;
		const locations = Object.keys(claims).filter((k) => k !== "id_token");
		expect(locations).toHaveLength(1);
		expect(Object.values(claims[locations[0]])).toEqual([null]);
		expect(last()).toMatchObject({ src: "AddRandomLocationClaimsToAuthorizationEndpointRequest", result: "SUCCESS" });
	});
});

/** An authorization response with `query` in the URL query (the code flow) and `fragment` in the fragment */
const queryResponse = (
	query: Record<string, string>,
	fragment: Record<string, string> = {},
): AuthorizationResponse => ({
	params: query,
	query,
	fragment,
	method: "GET",
	headers: {},
});

describe("the error responses of the FAPI 2 negative modules", () => {
	test("DetectWhetherErrorResponseIsInQueryOrFragment picks the part carrying error", () => {
		const inQuery = queryResponse({ error: "invalid_request" });
		detectWhetherErrorResponseIsInQueryOrFragment(inQuery);
		expect(inQuery.params).toBe(inQuery.query);
		expect(last()).toMatchObject({ msg: "Server has chosen to return 'error' in URL query, using query as response" });
		const inFragment = queryResponse({}, { error: "invalid_request" });
		detectWhetherErrorResponseIsInQueryOrFragment(inFragment);
		expect(inFragment.params).toBe(inFragment.fragment);
		expect(() => detectWhetherErrorResponseIsInQueryOrFragment(queryResponse({ code: "x" }))).toThrow(
			"authorization server did not return an error in the url query or fragment",
		);
	});

	test("EnsureUnsupportedResponseTypeOrInvalidRequestError", () => {
		ensureUnsupportedResponseTypeOrInvalidRequestError(
			queryResponse({ error: "unsupported_response_type" }),
			"OIDCC-3.3.2.6",
		);
		expect(last()).toMatchObject({
			result: "SUCCESS",
			permitted: ["invalid_request", "unsupported_response_type"],
			error: "unsupported_response_type",
		});
		expect(() => ensureUnsupportedResponseTypeOrInvalidRequestError(queryResponse({ error: "access_denied" }))).toThrow(
			"authorization endpoint response 'error' field has unexpected value",
		);
		expect(() => ensureUnsupportedResponseTypeOrInvalidRequestError(queryResponse({}))).toThrow(
			"Expected 'error' field is missing from authorization endpoint response",
		);
	});

	test("ExpectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest", () => {
		expectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest(
			queryResponse({ error: "access_denied" }),
		);
		expect(last()).toMatchObject({ result: "SUCCESS", msg: "error parameter is correctly 'access_denied'" });
		expect(() =>
			expectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest(queryResponse({ code: "x" })),
		).toThrow("error parameter not found. When running this test, the tester MUST press 'cancel'");
		expect(() =>
			expectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest(
				queryResponse({ error: "login_required" }),
			),
		).toThrow("error value is incorrect.");
		expect(last()).toMatchObject({ expected: "access_denied", actual: "login_required" });
	});
});

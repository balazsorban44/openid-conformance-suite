import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	addIdTokenEssentialNameClaimToAuthorizationEndpointRequest,
	checkErrorFromAuthorizationEndpointErrorInvalidRequest,
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
});

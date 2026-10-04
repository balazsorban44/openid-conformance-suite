import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	addBadRequestUriToAuthorizationRequest,
	addClientIdToAuthorizationEndpointRequest,
	addIdTokenEssentialNameClaimToAuthorizationEndpointRequest,
	addIncorrectNonceToAuthorizationEndpointRequest,
	addIncorrectStateToAuthorizationEndpointRequest,
	checkErrorFromAuthorizationEndpointErrorInvalidRequest,
	checkErrorFromAuthorizationEndpointErrorInvalidRequestOrInvalidRequestObject,
	checkErrorFromAuthorizationEndpointErrorInvalidRequestOrInvalidRequestObjectOrInvalidRequestUri,
	createPlainCodeChallenge,
	ensureInvalidRequestInvalidRequestObjectOrInvalidRequestUriError,
	ensureInvalidRequestUriError,
	extractAccessTokenFromAuthorizationResponse,
	extractIdTokenFromAuthorizationResponse,
	validateIdTokenFromAuthorizationResponseEncryption,
	warningAboutRequestUriError,
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

describe("the errors the FAPI 2.0 request_uri and request object modules permit", () => {
	test("invalid_request_uri only (EnsureInvalidRequestUriError)", () => {
		ensureInvalidRequestUriError(fragmentResponse({ error: "invalid_request_uri" }), "PAR-2.2");
		expect(last()).toMatchObject({
			src: "EnsureInvalidRequestUriError",
			result: "SUCCESS",
			msg: "Authorization endpoint returned expected 'error' of 'invalid_request_uri'",
			requirements: ["PAR-2.2"],
		});
		expect(() => ensureInvalidRequestUriError(fragmentResponse({ error: "invalid_request" }))).toThrow(ConditionFailed);
		expect(last()).toMatchObject({ msg: "'error' field has unexpected value", expected: "invalid_request_uri" });
		expect(() => ensureInvalidRequestUriError(fragmentResponse({ code: "c" }))).toThrow(
			"Expected 'error' field not found",
		);
	});

	test("the AbstractEnsureAuthorizationEndpointError messages differ from the other permitted-error conditions", () => {
		ensureInvalidRequestInvalidRequestObjectOrInvalidRequestUriError(
			fragmentResponse({ error: "invalid_request_object" }),
			"PAR-3-3",
		);
		expect(last()).toMatchObject({
			src: "EnsureInvalidRequestInvalidRequestObjectOrInvalidRequestUriError",
			result: "SUCCESS",
			msg: "Authorization endpoint returned 'error'",
			permitted: ["invalid_request", "invalid_request_object", "invalid_request_uri"],
			error: "invalid_request_object",
		});
		expect(() =>
			ensureInvalidRequestInvalidRequestObjectOrInvalidRequestUriError(fragmentResponse({ code: "c" })),
		).toThrow("The server was expected to return an error, but no error was returned");
		expect(() =>
			ensureInvalidRequestInvalidRequestObjectOrInvalidRequestUriError(fragmentResponse({ error: "access_denied" })),
		).toThrow("'error' field has unexpected value");
	});

	test("CheckErrorFromAuthorizationEndpointError... list the expected values", () => {
		checkErrorFromAuthorizationEndpointErrorInvalidRequestOrInvalidRequestObject(
			fragmentResponse({ error: "invalid_request" }),
			"OIDCC-3.1.2.6",
		);
		expect(last()).toMatchObject({
			src: "CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrInvalidRequestObject",
			result: "SUCCESS",
			msg: "Authorization endpoint returned expected error",
			expected: ["invalid_request_object", "invalid_request"],
			actual: "invalid_request",
		});
		checkErrorFromAuthorizationEndpointErrorInvalidRequestOrInvalidRequestObjectOrInvalidRequestUri(
			fragmentResponse({ error: "invalid_request_uri" }),
		);
		expect(last()).toMatchObject({
			result: "SUCCESS",
			expected: ["invalid_request_object", "invalid_request", "invalid_request_uri"],
		});
		expect(() =>
			checkErrorFromAuthorizationEndpointErrorInvalidRequestOrInvalidRequestObject(
				fragmentResponse({ error: "invalid_request_uri" }),
			),
		).toThrow("'error' field has unexpected value");
		expect(() => warningAboutRequestUriError("FAPI2-SP-FINAL-5.3.2.2")).toThrow(
			"The server rejected reuse of the 'request_uri' prior to authentication completion.",
		);
		expect(last()).toMatchObject({ src: "WarningAboutRequestUriError", requirements: ["FAPI2-SP-FINAL-5.3.2.2"] });
	});

	test("the parameters the modules add outside the request object", () => {
		const params: Record<string, unknown> = { client_id: "c1", state: "s", nonce: "n" };
		addIncorrectNonceToAuthorizationEndpointRequest(params);
		expect(params["nonce"]).toMatch(/^[A-Za-z0-9]{10}$/);
		expect(params["nonce"]).not.toBe("n");
		expect(last()).toMatchObject({
			src: "AddIncorrectNonceToAuthorizationEndpointRequest",
			msg: "Added incorrect nonce parameter to request",
			nonce: params["nonce"],
		});
		addIncorrectStateToAuthorizationEndpointRequest(params);
		expect(params["state"]).toMatch(/^[A-Za-z0-9]{10}$/);
		expect(last()).toMatchObject({ src: "AddIncorrectStateToAuthorizationEndpointRequest", state: params["state"] });
		addClientIdToAuthorizationEndpointRequest(params, { client_id: "c2" }, "PAR-4");
		expect(params["client_id"]).toBe("c2");
		expect(last()).toMatchObject({
			src: "AddClientIdToAuthorizationEndpointRequest",
			msg: "Added client_id of 'c2' to authorization endpoint request",
			requirements: ["PAR-4"],
		});
		expect(() => addClientIdToAuthorizationEndpointRequest(params, { client_id: "" })).toThrow(
			"client_id missing/empty in client object",
		);
		addBadRequestUriToAuthorizationRequest(params, "PAR-2");
		expect(params["request_uri"]).toBe("urn%3Aexample%3Abwc4JK-ESC0w8acc191e-Y1LTC2");
		expect(last()).toMatchObject({
			src: "AddBadRequestUriToAuthorizationRequest",
			msg: "Added bad request_uri to request object",
			request_uri: "urn%3Aexample%3Abwc4JK-ESC0w8acc191e-Y1LTC2",
		});
	});

	test("a plain code challenge is the verifier itself", () => {
		expect(createPlainCodeChallenge("verifier-1")).toEqual({
			codeChallenge: "verifier-1",
			codeChallengeMethod: "plain",
		});
		expect(last()).toMatchObject({ src: "CreatePlainCodeChallenge", code_challenge: "verifier-1" });
		expect(() => createPlainCodeChallenge("")).toThrow("code_verifier was null or empty");
	});
});

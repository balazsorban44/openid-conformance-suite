import { http, HttpResponse } from "msw";
import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { useMswServer, useTestLog } from "../suite/testing.ts";
import {
	addBadRequestUriToRequestParameters,
	buildRequestObjectPostToPAREndpoint,
	buildUnsignedPAREndpointRequest,
	callPAREndpoint,
	checkErrorFromParEndpointResponseErrorInvalidClientOrInvalidRequest,
	checkForPARResponseExpiresIn,
	checkForRequestUriValue,
	checkPAREndpointResponse201WithNoError,
	ensureMinimumRequestUriEntropy,
	ensureParHTTPError,
	ensurePARInvalidRequestError,
	ensurePARInvalidRequestOrInvalidDpopProof,
	ensurePARInvalidRequestOrInvalidRequestObjectError,
	ensurePARInvalidRequestOrInvalidRequestObjectOrRequestUriNotSupportedError,
	extractRequestUriFromPARResponse,
	type ParResponse,
} from "./par.ts";

const t = useTestLog();
const server = useMswServer();

const metadata = {
	issuer: "https://op.example",
	pushed_authorization_request_endpoint: "https://op.example/par",
};

function response(status: number, json: Record<string, unknown> | null): ParResponse {
	return { status, endpoint_name: "par", headers: { "content-type": "application/json" }, body: null, json };
}

describe("the PAR request", () => {
	test("unsigned: the authorization request parameters as the form; signed: the request object", () => {
		const params = { client_id: "c1", scope: "openid", response_type: "code" };
		const unsigned = buildUnsignedPAREndpointRequest(params);
		expect(unsigned.form).toEqual(params);
		expect(unsigned.form).not.toBe(params);
		const signed = buildRequestObjectPostToPAREndpoint("a.b.c");
		expect(signed.form).toEqual({ request: "a.b.c" });
		expect(t.entries().map((e) => [e.src, e["result"]])).toEqual([
			["BuildUnsignedPAREndpointRequest", "SUCCESS"],
			["BuildRequestObjectPostToPAREndpoint", "SUCCESS"],
		]);
	});

	test("is POSTed form-urlencoded with the request's headers; the JSON body is parsed", async () => {
		let body = "";
		let contentType: string | null = null;
		let dpop: string | null = null;
		server.use(
			http.post("https://op.example/par", async ({ request }) => {
				body = await request.text();
				contentType = request.headers.get("content-type");
				dpop = request.headers.get("dpop");
				return HttpResponse.json({ request_uri: "urn:x:1", expires_in: 90 }, { status: 201 });
			}),
		);
		const req = buildUnsignedPAREndpointRequest({ client_id: "c 1", scope: "openid" });
		req.headers["DPoP"] = "proof";
		const res = await callPAREndpoint({ metadata }, req, { requirements: ["PAR-2.1"] });
		expect(body).toBe("client_id=c+1&scope=openid");
		expect(contentType).toMatch(/^application\/x-www-form-urlencoded/);
		expect(dpop).toBe("proof");
		expect(res.status).toBe(201);
		expect(res.json).toEqual({ request_uri: "urn:x:1", expires_in: 90 });
		expect(
			t
				.entries()
				.slice(1)
				.map((e) => [e.src, e["msg"], e["result"], e["requirements"]]),
		).toEqual([
			["CallPAREndpoint", "HTTP request", undefined, undefined],
			["CallPAREndpoint", "HTTP response", undefined, undefined],
			["CallPAREndpoint", "Parsed pushed authorization request endpoint response", "SUCCESS", ["PAR-2.1"]],
		]);
	});
});

describe("the PAR response checks", () => {
	test("201 without error, a valid request_uri and expires_in (PAR-2.2)", () => {
		const res = response(201, {
			request_uri: "urn:ietf:params:oauth:request_uri:5haiCxMl-1CmPOJQajT_do89um1s4wxJE4oiv_1H-DD",
			expires_in: 90.7,
		});
		checkPAREndpointResponse201WithNoError(res, "PAR-2.2");
		checkForRequestUriValue(res, "PAR-2.2");
		checkForPARResponseExpiresIn(res, "PAR-2.2");
		expect(extractRequestUriFromPARResponse(res)).toEqual({
			requestUri: "urn:ietf:params:oauth:request_uri:5haiCxMl-1CmPOJQajT_do89um1s4wxJE4oiv_1H-DD",
			expiresIn: 90,
		});
		ensureMinimumRequestUriEntropy(res, "PAR-2.2");
		expect(t.entries().map((e) => [e.src, e["result"]])).toEqual([
			["CheckPAREndpointResponse201WithNoError", "SUCCESS"],
			["CheckForRequestUriValue", "SUCCESS"],
			["CheckForPARResponseExpiresIn", "SUCCESS"],
			["ExtractRequestUriFromPARResponse", "SUCCESS"],
			["EnsureMinimumRequestUriEntropy", "SUCCESS"],
		]);
		expect(t.entries()[2]).toMatchObject({ expires_in: 90 });
	});

	test("the failures: a 400, an error with a 201, a malformed request_uri, a too short expires_in", () => {
		expect(() => checkPAREndpointResponse201WithNoError(response(400, { error: "invalid_request" }))).toThrow(
			"Invalid pushed authorization request endpoint response http status code",
		);
		expect(() => checkPAREndpointResponse201WithNoError(response(201, { error: "x" }))).toThrow(
			"pushed authorization request endpoint error response.",
		);
		expect(() => checkForRequestUriValue(response(201, { request_uri: "urn:x y" }))).toThrow(
			"request_uri is malformed and does not seem to conform to RFC 2396",
		);
		expect(() => checkForRequestUriValue(response(201, {}))).toThrow(
			"request_uri is missing or empty in pushed authorization response",
		);
		expect(() => checkForPARResponseExpiresIn(response(201, { expires_in: 3 }))).toThrow(
			"expires_in too short and is unlikely to give the client enough time to use the request_uri",
		);
		expect(() => checkForPARResponseExpiresIn(response(201, { expires_in: "90" }))).toThrow(
			"expires_in is missing or empty in pushed authorization response",
		);
		expect(() =>
			ensureMinimumRequestUriEntropy(response(201, { request_uri: "urn:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" })),
		).toThrow(ConditionFailed);
	});

	test("the expected errors of the negative modules (PAR-2.3)", () => {
		ensurePARInvalidRequestError(response(400, { error: "invalid_request" }), "RFC7636-4.4.1");
		ensurePARInvalidRequestOrInvalidDpopProof(response(400, { error: "invalid_dpop_proof" }), "DPOP-10.1");
		checkErrorFromParEndpointResponseErrorInvalidClientOrInvalidRequest(response(401, { error: "invalid_client" }));
		expect(t.entries().map((e) => [e.src, e["result"], e["msg"]])).toEqual([
			[
				"EnsurePARInvalidRequestError",
				"SUCCESS",
				"Pushed Authorization Request Endpoint returned expected 'error' of '[invalid_request]'",
			],
			[
				"EnsurePARInvalidRequestOrInvalidDpopProof",
				"SUCCESS",
				"Pushed Authorization Request Endpoint returned expected 'error' of '[invalid_request, invalid_dpop_proof]'",
			],
			[
				"CheckErrorFromParEndpointResponseErrorInvalidClientOrInvalidRequest",
				"SUCCESS",
				"pushed_authorization_endpoint_response error returned expected 'error' of 'invalid_client'",
			],
		]);
		expect(() => ensurePARInvalidRequestError(response(201, { request_uri: "urn:x" }))).toThrow(
			"Invalid pushed authorization request endpoint response http status code",
		);
		expect(() => ensurePARInvalidRequestError(response(400, { error: "invalid_client" }))).toThrow(
			"'error' field has unexpected value",
		);
		expect(() => checkErrorFromParEndpointResponseErrorInvalidClientOrInvalidRequest(response(400, {}))).toThrow(
			"Expected 'error' field is not present in PAR response",
		);
	});

	test("the request_uri and http method modules: the errors they permit, a 4xx/5xx for a PUT, a request_uri form parameter", () => {
		ensurePARInvalidRequestOrInvalidRequestObjectOrRequestUriNotSupportedError(
			response(400, { error: "request_uri_not_supported" }),
			"PAR-2.1-2",
		);
		ensurePARInvalidRequestOrInvalidRequestObjectError(response(400, { error: "invalid_request_object" }), "JAR-6.2");
		ensureParHTTPError(response(405, null), "PAR-2.3");
		ensureParHTTPError(response(500, null), "PAR-2.3");
		expect(t.entries().map((e) => [e.src, e["result"], e["msg"], e["requirements"]])).toEqual([
			[
				"EnsurePARInvalidRequestOrInvalidRequestObjectOrRequestUriNotSupportedError",
				"SUCCESS",
				"Pushed Authorization Request Endpoint returned expected 'error' of '[invalid_request, invalid_request_object, request_uri_not_supported]'",
				["PAR-2.1-2"],
			],
			[
				"EnsurePARInvalidRequestOrInvalidRequestObjectError",
				"SUCCESS",
				"Pushed Authorization Request Endpoint returned expected 'error' of '[invalid_request, invalid_request_object]'",
				["JAR-6.2"],
			],
			[
				"EnsureParHTTPError",
				"SUCCESS",
				"Pushed Authorization Request Endpoint returned a HTTP 4xx or 5xx error as expected",
				["PAR-2.3"],
			],
			[
				"EnsureParHTTPError",
				"SUCCESS",
				"Pushed Authorization Request Endpoint returned a HTTP 4xx or 5xx error as expected",
				["PAR-2.3"],
			],
		]);
		expect(() => ensureParHTTPError(response(201, { request_uri: "urn:x" }))).toThrow(
			"Invalid pushed authorization request endpoint response http status code",
		);
		expect(() =>
			ensurePARInvalidRequestOrInvalidRequestObjectError(response(400, { error: "request_uri_not_supported" })),
		).toThrow("'error' field has unexpected value");

		const req = buildUnsignedPAREndpointRequest({ client_id: "c1" });
		const before = t.entries().length;
		addBadRequestUriToRequestParameters(req);
		expect(req.form["request_uri"]).toBe("urn:fdc:authlete.com:E2ooXxELkEFSKR90ymYV-BbwAvCC2TozHfSb_mMCw2s");
		expect(t.entries().length).toBe(before);
	});
});

import { http, HttpResponse } from "msw";
import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { useMswServer, useTestLog } from "../suite/testing.ts";
import { createEffectiveAuthorizationRequestParameters } from "./authorization.ts";
import {
	checkForUnexpectedClaimsInRequestObject,
	ensureOptionalAuthorizationRequestParametersMatchRequestObject,
	ensureRequestUriIsHttpsOrRequestObjectIsSigned,
	ensureRequiredAuthorizationRequestParametersMatchRequestObject,
	fetchRequestUriAndExtractRequestObject,
} from "./request-object.ts";

const t = useTestLog();
const server = useMswServer();
const lastEntry = () => t.entries().at(-1);

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const unsigned = (claims: Record<string, unknown>) => b64({ alg: "none" }) + "." + b64(claims) + ".";
const parsed = (claims: Record<string, unknown>, alg = "none") => ({ value: "x", header: { alg }, claims });

describe("request objects", () => {
	test("the request_uri is fetched and the request object parsed", async () => {
		server.use(http.get("https://rp.example/ro/1", () => HttpResponse.text(unsigned({ scope: "openid email" }))));
		const ro = await fetchRequestUriAndExtractRequestObject({ request_uri: "https://rp.example/ro/1" }, null, null);
		expect(ro.header).toEqual({ alg: "none" });
		expect(ro.claims).toEqual({ scope: "openid email" });
		expect(t.entries().map((e) => e.msg)).toEqual([
			"Fetching request object from request_uri",
			"HTTP request",
			"HTTP response",
			"Downloaded request object",
			"Parsed request object",
		]);
	});

	test("a request_uri answered with an error status fails the test", async () => {
		server.use(http.get("https://rp.example/ro/2", () => new HttpResponse("gone", { status: 404 })));
		await expect(
			fetchRequestUriAndExtractRequestObject({ request_uri: "https://rp.example/ro/2" }, null, null),
		).rejects.toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({
			src: "FetchRequestUriAndExtractRequestObject",
			msg: "Unable to fetch request_uri from https://rp.example/ro/2",
			result: "FAILURE",
		});
	});

	test("an unsigned request object needs an https request_uri, a signed one does not", () => {
		ensureRequestUriIsHttpsOrRequestObjectIsSigned({ request_uri: "https://rp.example/ro" }, parsed({}));
		ensureRequestUriIsHttpsOrRequestObjectIsSigned({ request_uri: "http://rp.example/ro" }, parsed({}, "RS256"));
		expect(lastEntry()).toMatchObject({ msg: "request_uri is not a https url but the request object is signed" });
		expect(() =>
			ensureRequestUriIsHttpsOrRequestObjectIsSigned({ request_uri: "http://rp.example/ro" }, parsed({})),
		).toThrow("MUST be https");
	});

	test("response_type and client_id must match, other parameters only warn (scope=openid is never reported)", () => {
		const ro = parsed({ response_type: "code", client_id: "c", scope: "openid email", state: "s1" });
		ensureRequiredAuthorizationRequestParametersMatchRequestObject({ response_type: "code", client_id: "c" }, ro);
		expect(() =>
			ensureRequiredAuthorizationRequestParametersMatchRequestObject({ response_type: "id_token", client_id: "c" }, ro),
		).toThrow("must match");
		ensureOptionalAuthorizationRequestParametersMatchRequestObject({ scope: "openid", state: "s1" }, ro);
		expect(lastEntry()).toMatchObject({ result: "SUCCESS" });
		expect(() =>
			ensureOptionalAuthorizationRequestParametersMatchRequestObject({ scope: "openid profile" }, ro),
		).toThrow("do not match");
		expect(lastEntry()).toMatchObject({
			scope: { "Value in http request": "openid profile", "Value in request object": "openid email" },
		});
	});

	test("the request object's claims override the request parameters", () => {
		const effective = createEffectiveAuthorizationRequestParameters(
			{ scope: "openid", request_uri: "https://rp.example/ro", max_age: "10" },
			parsed({ scope: "openid email", nonce: "n" }),
		);
		expect(effective).toEqual({ scope: "openid email", max_age: 10, nonce: "n" });
	});

	test("request and request_uri are not expected inside a request object", () => {
		checkForUnexpectedClaimsInRequestObject(parsed({ iss: "c", aud: "op", scope: "openid" }));
		expect(() => checkForUnexpectedClaimsInRequestObject(parsed({ request_uri: "x", foo: 1 }))).toThrow(
			"unknown claims",
		);
		expect(lastEntry()).toMatchObject({ unknown_claims: ["request_uri", "foo"] });
	});
});

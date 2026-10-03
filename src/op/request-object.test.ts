import { describe, expect, test } from "vitest";
import { useTestLog } from "../suite/testing.ts";
import {
	buildRequestObjectByReferenceRedirectToAuthorizationEndpoint,
	buildRequestObjectByValueRedirectToAuthorizationEndpoint,
	convertAuthorizationEndpointRequestToRequestObject,
	createRandomRequestUriWithFragment,
	serializeRequestObjectWithNullAlgorithm,
} from "./request-object.ts";

const t = useTestLog();
const op = { metadata: { authorization_endpoint: "https://op.example/auth" } };
const params = {
	client_id: "c1",
	redirect_uri: "https://suite.example/cb",
	scope: "openid",
	state: "s",
	nonce: "n",
	response_type: "code",
};

describe("request object by value", () => {
	test("the object is the request as an unsecured JWT (alg none, empty signature)", () => {
		const claims = convertAuthorizationEndpointRequestToRequestObject(params);
		const jwt = serializeRequestObjectWithNullAlgorithm(claims);
		const [header, payload, signature] = jwt.split(".");
		expect(JSON.parse(Buffer.from(header, "base64url").toString())).toEqual({ alg: "none" });
		expect(JSON.parse(Buffer.from(payload, "base64url").toString())).toEqual(params);
		expect(signature).toBe("");
		expect(claims).not.toBe(params);
	});

	test("the url carries request plus response_type, client_id, scope and redirect_uri (OIDCC-6.1), sorted, and nothing the object has", () => {
		const claims = convertAuthorizationEndpointRequestToRequestObject(params);
		const url = new URL(buildRequestObjectByValueRedirectToAuthorizationEndpoint(op, params, claims, "a.b."));
		expect([...url.searchParams.keys()]).toEqual(["client_id", "redirect_uri", "request", "response_type", "scope"]);
		expect(url.searchParams.get("request")).toBe("a.b.");
		expect(url.searchParams.has("state")).toBe(false);
		expect(url.searchParams.has("nonce")).toBe(false);
	});

	test("a request parameter that differs from the object is sent too (the invalid redirect_uri of the redirect_uri module)", () => {
		const claims = convertAuthorizationEndpointRequestToRequestObject(params);
		const changed = { ...params, redirect_uri: "https://suite.example/cb_invalid", extra: "foobar" };
		const url = new URL(buildRequestObjectByValueRedirectToAuthorizationEndpoint(op, changed, claims, "a.b."));
		expect(url.searchParams.get("redirect_uri")).toBe("https://suite.example/cb_invalid");
		// not in the object: sent as a plain parameter
		expect(url.searchParams.get("extra")).toBe("foobar");
	});
});

describe("request object by reference", () => {
	test("request_uri keeps its fragment and is a 64 character path below the suite", () => {
		const requestUri = createRandomRequestUriWithFragment("https://suite.example/test/a/x", "OIDCC-6.2");
		expect(requestUri.path).toMatch(/^requesturi\/[A-Za-z0-9]{64}$/);
		expect(requestUri.fullUrl).toMatch(
			new RegExp("^https://suite\\.example/test/a/x/" + requestUri.path + "#[A-Za-z0-9_-]{43}$"),
		);
		const claims = convertAuthorizationEndpointRequestToRequestObject(params);
		const url = new URL(buildRequestObjectByReferenceRedirectToAuthorizationEndpoint(op, params, claims, requestUri));
		expect(url.searchParams.get("request_uri")).toBe(requestUri.fullUrl);
		expect(t.entries().find((e) => e.src === "CreateRandomRequestUriWithFragment")?.["requirements"]).toEqual([
			"OIDCC-6.2",
		]);
	});
});

describe("serializeRequestObjectWithNullAlgorithm", () => {
	test("claims with null values are left out (JWTClaimsSet.toJSONObject())", () => {
		const jwt = serializeRequestObjectWithNullAlgorithm({ a: "b", gone: null });
		const [, claims] = jwt.split(".");
		expect(JSON.parse(Buffer.from(claims, "base64url").toString())).toEqual({ a: "b" });
	});
});

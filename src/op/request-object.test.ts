import { describe, expect, test } from "vitest";
import { generateJwkForAlg, publicJwks } from "../suite/jose.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	addBadAudToRequestObject,
	addExpValueIs70MinutesInFutureToRequestObject,
	addNbfValueIs70MinutesInPastToRequestObject,
	addNbfValueIs8SecondsInFutureToRequestObject,
	buildRequestObjectByReferenceRedirectToAuthorizationEndpoint,
	buildRequestObjectByReferenceRedirectToAuthorizationEndpointExposingState,
	buildRequestObjectByValueRedirectToAuthorizationEndpoint,
	convertAuthorizationEndpointRequestToRequestObject,
	createRandomRequestUriWithFragment,
	invalidateRequestObjectSignature,
	removeRedirectUriFromRequestObject,
	serializeRequestObjectWithNullAlgorithm,
	signRequestObject,
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

describe("the negative request object modules (FAPI 2.0 message signing)", () => {
	test("the state is exposed in the query although the request object has it (expose_state_in_authorization_endpoint_request)", () => {
		const claims = convertAuthorizationEndpointRequestToRequestObject(params);
		const hidden = new URL(
			buildRequestObjectByReferenceRedirectToAuthorizationEndpoint(op, params, claims, "urn:par:1", "PAR-4"),
		);
		expect(hidden.searchParams.has("state")).toBe(false);
		const exposed = new URL(
			buildRequestObjectByReferenceRedirectToAuthorizationEndpointExposingState(op, params, claims, "urn:par:1", "s"),
		);
		expect(exposed.searchParams.get("state")).toBe("s");
		expect(exposed.searchParams.get("request_uri")).toBe("urn:par:1");
		expect([...exposed.searchParams.keys()]).toEqual([
			"client_id",
			"redirect_uri",
			"request_uri",
			"response_type",
			"scope",
			"state",
		]);
		expect(t.entries().at(-1)?.src).toBe("BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint");
	});

	test("the claim changes are logged with the claims and the time as java.time.Instant prints it", () => {
		const claims: Record<string, unknown> = { ...params, aud: "https://op.example" };
		const now = Math.floor(Date.now() / 1000);
		addNbfValueIs8SecondsInFutureToRequestObject(claims, "FAPI2-SP-FINAL-5.3.2.1");
		expect(claims["nbf"]).toBeGreaterThanOrEqual(now + 8);
		addExpValueIs70MinutesInFutureToRequestObject(claims, "OIDCC-6.1", "RFC7519-4.1.4");
		expect(claims["exp"]).toBeGreaterThanOrEqual(now + 70 * 60);
		addNbfValueIs70MinutesInPastToRequestObject(claims, "FAPI2-MS-ID1-5.3.1-3");
		expect(claims["nbf"]).toBeLessThanOrEqual(now - 70 * 60);
		addBadAudToRequestObject(claims, "OIDCC-6.1", "RFC7519-4.1.3");
		expect(claims["aud"]).toBe("https://www.other1.example.com/");
		removeRedirectUriFromRequestObject(claims);
		expect(claims).not.toHaveProperty("redirect_uri");
		const entries = t.entries();
		expect(entries.map((e) => [e.src, e["result"], e["requirements"]])).toEqual([
			["AddNbfValueIs8SecondsInFutureToRequestObject", "SUCCESS", ["FAPI2-SP-FINAL-5.3.2.1"]],
			["AddExpValueIs70MinutesInFutureToRequestObject", "SUCCESS", ["OIDCC-6.1", "RFC7519-4.1.4"]],
			["AddNbfValueIs70MinutesInPastToRequestObject", "SUCCESS", ["FAPI2-MS-ID1-5.3.1-3"]],
			["AddBadAudToRequestObject", "SUCCESS", ["OIDCC-6.1", "RFC7519-4.1.3"]],
			["RemoveRedirectUriFromRequestObject", "SUCCESS", undefined],
		]);
		expect(entries[0]?.["nbf_is_8_seconds_in_the_future"]).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
		// UPSTREAM: the exp condition names its field iat_...
		expect(entries[1]?.["iat_is_70_minutes_in_the_future"]).toMatch(/Z$/);
		expect(entries[2]?.["nbf_is_70_minutes_in_the_past"]).toMatch(/Z$/);
		expect(entries[3]?.["aud"]).toBe("https://www.other1.example.com/");
		expect(entries[4]?.["request_object_claims"]).toEqual(claims);
	});

	test("an invalidated signature keeps the header and claims and flips the signature bits", async () => {
		const key = await generateJwkForAlg("PS256");
		const keys = { jwks: { keys: [key] }, publicJwks: publicJwks({ keys: [key] }) };
		const signed = await signRequestObject({ ...params, aud: "https://op.example" }, { keys });
		const invalid = invalidateRequestObjectSignature(signed);
		const [h, p, s] = signed.split(".");
		const [ih, ip, is] = invalid.split(".");
		expect([ih, ip]).toEqual([h, p]);
		expect(is).not.toBe(s);
		expect(Buffer.from(is as string, "base64url").length).toBe(Buffer.from(s as string, "base64url").length);
		expect(t.entries().at(-1)).toMatchObject({
			src: "InvalidateRequestObjectSignature",
			msg: "Made the request_object signature invalid",
			request_object: invalid,
		});
		expect(() => invalidateRequestObjectSignature("not.a.jwt")).toThrow("Couldn't parse JWT");
	});
});

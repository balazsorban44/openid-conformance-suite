import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	checkRequestClaimsParameterMemberValues,
	createEffectiveAuthorizationRequestParameters,
	disallowMaxAgeEqualsZeroAndPromptNone,
	ensureResponseTypeIs,
	ensureValidRedirectUriForAuthorizationEndpointRequest,
	sendAuthorizationResponseWithResponseModeFragment,
	sendAuthorizationResponseWithResponseModeQuery,
} from "./authorization.ts";
import { oidccValidateClientRedirectUris } from "./registration.ts";

const t = useTestLog();
const lastEntry = () => t.entries().at(-1);

describe("authorization request checks", () => {
	test("response_type matches in any order, but not a subset", () => {
		ensureResponseTypeIs({ response_type: "id_token code" }, "code id_token");
		expect(lastEntry()).toMatchObject({ src: "EnsureResponseTypeIsCodeIdToken", result: "SUCCESS" });
		expect(() => ensureResponseTypeIs({ response_type: "code" }, "code id_token")).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({
			msg: "Response type is not expected value",
			actual: "code",
			result: "FAILURE",
		});
	});

	test("max_age arrives as a string and becomes a number, so max_age=0 with prompt=none is caught", () => {
		const params = createEffectiveAuthorizationRequestParameters({ max_age: "0", prompt: "none", request_uri: "x" });
		expect(params).toEqual({ max_age: 0, prompt: "none" });
		expect(() => disallowMaxAgeEqualsZeroAndPromptNone(params)).toThrow(
			"Login required. Request contains max_age=0 and prompt=none parameters",
		);
	});

	test("the redirect_uri must be registered; http is only allowed for code flow web clients", () => {
		const client = { client_id: "c", redirect_uris: ["http://rp.example/cb"] };
		expect(
			ensureValidRedirectUriForAuthorizationEndpointRequest(client, {
				redirect_uri: "http://rp.example/cb",
				response_type: "code",
			}),
		).toBe("http://rp.example/cb");
		expect(() =>
			ensureValidRedirectUriForAuthorizationEndpointRequest(client, {
				redirect_uri: "http://rp.example/cb",
				response_type: "code id_token",
			}),
		).toThrow("uses http scheme which is not allowed");
		expect(() =>
			ensureValidRedirectUriForAuthorizationEndpointRequest(client, { redirect_uri: "http://rp.example/other" }),
		).toThrow("redirect_uri is not one of the allowed ones");
	});

	test("claims parameter members other than essential/value/values are reported with their path", () => {
		expect(() =>
			checkRequestClaimsParameterMemberValues({
				claims: { id_token: { email: { essential: true }, name: { foo: 1 } }, userinfo: { phone_number: null } },
			}),
		).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({
			// a claim is logged under the object that contains it ("id_token": "name" for id_token.name.foo)
			claim_members: { id_token: ["email", "name"], userinfo: ["phone_number"] },
			invalid_claims: { id_token: ["name"] },
		});
	});
});

describe("registration checks", () => {
	test("web clients using implicit must register https redirect_uris that are not localhost", () => {
		expect(() =>
			oidccValidateClientRedirectUris({
				response_types: ["id_token"],
				redirect_uris: ["http://rp.example/cb", "https://localhost/cb", "https://rp.example/cb"],
			}),
		).toThrow("redirect_uris validation failed");
		expect(lastEntry()?.["errors"]).toEqual([
			{
				failure_reason:
					"Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris",
				details: { uri: "http://rp.example/cb" },
			},
			{
				failure_reason: "Web Clients using the OAuth Implicit Grant Type MUST not use localhost as the hostname",
				details: { uri: "https://localhost/cb", host: "localhost" },
			},
		]);
	});
});

describe("authorization responses", () => {
	test("query: parameters appended to the redirect_uri; fragment: form-encoded after #", () => {
		const params = { redirect_uri: "https://rp.example/cb?x=1", state: "a b", code: "c" };
		expect(sendAuthorizationResponseWithResponseModeQuery({ ...params })).toBe(
			"https://rp.example/cb?x=1&state=a%20b&code=c",
		);
		expect(sendAuthorizationResponseWithResponseModeFragment({ ...params, id_token: "t" })).toBe(
			"https://rp.example/cb?x=1#state=a%20b&code=c&id_token=t",
		);
	});
});

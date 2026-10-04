import { http, HttpResponse } from "msw";
import { describe, expect, test } from "vitest";
import { useMswServer, useTestLog } from "../suite/testing.ts";
import { scopesNotSupportedReason } from "./discovery.ts";
import type { OpVariant } from "./op.ts";
import {
	addIdentityClaimsFromUserInfo,
	callUserInfoEndpoint,
	callUserInfoEndpointWithBearerTokenInBody,
	checkForUnexpectedClaimsInUserinfo,
	ensureIdentityClaimsContainRequestedClaims,
	ensureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources,
	validateExtractedUserInfoResponse,
	validateReturnedClaimsUserInfoResponse,
	verifyScopesReturnedInUserInfoClaims,
} from "./userinfo.ts";

const t = useTestLog();
const server = useMswServer();

const metadata = { issuer: "https://op.example", userinfo_endpoint: "https://op.example/me" };
const accessToken = { value: "at-1", type: "Bearer" };

describe("userinfo endpoint calls", () => {
	test("GET sends the token in the Authorization header and logs under CallUserInfoEndpoint", async () => {
		let authorization: string | null = null;
		server.use(
			http.get("https://op.example/me", ({ request }) => {
				authorization = request.headers.get("authorization");
				return HttpResponse.json({ sub: "foo" });
			}),
		);
		const res = await callUserInfoEndpoint({ metadata }, accessToken, {}, "OIDCC-5.3.1");
		expect(authorization).toBe("Bearer at-1");
		expect(res.status).toBe(200);
		const last = t.entries().at(-1);
		expect(last).toMatchObject({
			src: "CallUserInfoEndpoint",
			msg: "Got a response from the userinfo endpoint",
			result: "SUCCESS",
			requirements: ["OIDCC-5.3.1"],
			status_code: { code: 200 },
		});
	});

	test("the token in the body: a form POST without an Authorization header", async () => {
		let authorization: string | null = null;
		let contentType: string | null = null;
		let body = "";
		server.use(
			http.post("https://op.example/me", async ({ request }) => {
				authorization = request.headers.get("authorization");
				contentType = request.headers.get("content-type");
				body = await request.text();
				return HttpResponse.json({ error: "invalid_request" }, { status: 400 });
			}),
		);
		const res = await callUserInfoEndpointWithBearerTokenInBody({ metadata }, accessToken, "OIDCC-5.3.1");
		expect(authorization).toBeNull();
		expect(contentType).toBe("application/x-www-form-urlencoded");
		expect(body).toBe("access_token=at-1");
		// any HTTP status is a response, the test decides what a 400 means
		expect(res.status).toBe(400);
		expect(t.entries().at(-1)).toMatchObject({ src: "CallUserInfoEndpointWithBearerTokenInBody", result: "SUCCESS" });
	});
});

describe("verifyScopesReturnedInUserInfoClaims", () => {
	test("fails naming the missing claims of the requested scopes (OIDCC-5.4)", () => {
		const request = { params: { scope: "openid email" } };
		expect(() => verifyScopesReturnedInUserInfoClaims({ sub: "foo", email: "a@b" }, request, "OIDCC-5.4")).toThrow(
			/doesn't contain all scope items/,
		);
		expect(t.entries().at(-1)).toMatchObject({
			result: "FAILURE",
			missing_items: ["email_verified"],
			requirements: ["OIDCC-5.4"],
		});
	});

	test("succeeds when every claim of every scope is there", () => {
		const request = { params: { scope: "openid email" } };
		verifyScopesReturnedInUserInfoClaims({ sub: "foo", email: "a@b", email_verified: true }, request);
		expect(t.entries().at(-1)).toMatchObject({
			result: "SUCCESS",
			expected_scope_items: ["sub", "email", "email_verified"],
		});
	});
});

const idToken = (sub: string) => ({ value: "x", header: {}, claims: { sub } });

describe("the userinfo's sub and the flow's id_tokens", () => {
	const userinfo = { sub: "foo", name: "Jane", email: "a@b", email_verified: true };

	test("the userinfo modules compare with the token endpoint's id_token only when there is an authorization endpoint one", () => {
		validateExtractedUserInfoResponse(userinfo, {
			authorizationEndpointIdToken: null,
			tokenEndpointIdToken: idToken("x"),
		});
		expect(t.entries().filter((e) => String(e.src).startsWith("VerifyUserInfoAndIdToken"))).toEqual([]);

		validateExtractedUserInfoResponse(userinfo, {
			authorizationEndpointIdToken: idToken("foo"),
			tokenEndpointIdToken: idToken("bar"),
		});
		expect(
			t
				.entries()
				.filter((e) => String(e.src).startsWith("VerifyUserInfoAndIdToken"))
				.map((e) => [e.src, e["result"], e["msg"]]),
		).toEqual([
			[
				"VerifyUserInfoAndIdTokenInAuthorizationEndpointSameSub",
				"SUCCESS",
				"userinfo response and id_token sub are the same",
			],
			[
				"VerifyUserInfoAndIdTokenInTokenEndpointSameSub",
				"FAILURE",
				'"sub" in user info response doesn\'t match with "sub" in token_endpoint_id_token',
			],
		]);
	});

	test("the returned claims modules compare with every id_token of the flow", () => {
		validateReturnedClaimsUserInfoResponse(
			userinfo,
			{ authorizationEndpointIdToken: idToken("bar"), tokenEndpointIdToken: null },
			{ params: { scope: "openid email" } },
		);
		expect(t.entries().find((e) => e.src === "VerifyUserInfoAndIdTokenInAuthorizationEndpointSameSub")).toMatchObject({
			result: "FAILURE",
			msg: '"sub" in user info response doesn\'t match with "sub" in authorization_endpoint_id_token',
			requirements: ["OIDCC-5.3.2"],
		});
		expect(t.entries().at(-1)).toMatchObject({ src: "VerifyScopesReturnedInUserInfoClaims", result: "SUCCESS" });
	});
});

describe("ensureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources", () => {
	test("a source that no claim name references fails (OIDCC-5.6.2)", () => {
		expect(() =>
			ensureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources({
				_claim_names: { address: "src1" },
				_claim_sources: { src1: {}, src2: {} },
			}),
		).toThrow(/Member name 'src2'/);
	});

	test("only one of the two members fails", () => {
		expect(() => ensureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources({ _claim_names: {} })).toThrow(
			/contains '_claim_names' but not _claim_sources'/,
		);
	});
});

const variant = (server_metadata: string) => ({ server_metadata }) as OpVariant;

describe("scopesNotSupportedReason", () => {
	test("static server metadata: the scopes are not checked", () => {
		expect(
			scopesNotSupportedReason({ metadata, variant: variant("static") }, { client_id: "c", scope: "openid email" }),
		).toBeNull();
		expect(t.entries()).toEqual([]);
	});

	test("discovery without the requested scope: INFO entry and a reason to skip", () => {
		const reason = scopesNotSupportedReason(
			{ metadata: { ...metadata, scopes_supported: ["openid", "profile"] }, variant: variant("discovery") },
			{ client_id: "c", scope: "openid email" },
		);
		expect(reason).toMatch(/so the test has been skipped/);
		expect(t.entries().at(-1)).toMatchObject({
			src: "OIDCCCheckScopesSupportedContainScopeTest",
			result: "INFO",
			msg: "'scopes_support' in discovery document doesn't contain expected scopes",
		});
	});

	test("discovery listing the scopes: no skip", () => {
		const reason = scopesNotSupportedReason(
			{ metadata: { ...metadata, scopes_supported: ["openid", "email"] }, variant: variant("discovery") },
			{ client_id: "c", scope: "openid email" },
		);
		expect(reason).toBeNull();
	});
});

describe("the identity claims of the claims parameter module", () => {
	test("AddIdentityClaimsFromUserInfo merges the userinfo claims, equal values where both have the claim", () => {
		const identity: Record<string, unknown> = { sub: "u", name: "Foo", address: { country: "US" } };
		addIdentityClaimsFromUserInfo(identity, { sub: "u", email: "foo@example.com", address: { country: "US" } });
		expect(identity).toEqual({ sub: "u", name: "Foo", email: "foo@example.com", address: { country: "US" } });
		expect(t.entries().at(-1)).toMatchObject({
			src: "AddIdentityClaimsFromUserInfo",
			result: "SUCCESS",
			msg: "Merged identity claims from userinfo with those from id_token",
		});
		expect(() => addIdentityClaimsFromUserInfo({ sub: "u", name: "Foo" }, { name: "Bar" })).toThrow(
			"Value of name differs between id_token and userinfo",
		);
	});

	test("EnsureIdentityClaimsContainRequestedClaims compares with claims.userinfo of the request", () => {
		const request = { claims: { userinfo: { sub: null, name: { essential: true }, email: {} } } };
		ensureIdentityClaimsContainRequestedClaims({ sub: "u", name: "Foo", email: "e" }, request, "OIDCC-5.5");
		expect(t.entries().at(-1)).toMatchObject({
			result: "SUCCESS",
			msg: "id_token and userinfo combined contain all the requested claims",
		});
		expect(() => ensureIdentityClaimsContainRequestedClaims({ sub: "u" }, request)).toThrow(
			"The server did not return all the requested claims.",
		);
		expect(t.entries().at(-1)).toMatchObject({ missing: ["name", "email"] });
	});

	test("CheckForUnexpectedClaimsInUserinfo", () => {
		checkForUnexpectedClaimsInUserinfo({}, "OIDCC-5.1");
		expect(t.entries().at(-1)).toMatchObject({
			result: "SUCCESS",
			msg: "userinfo response includes only known claims",
		});
		expect(() => checkForUnexpectedClaimsInUserinfo({ custom: 1 })).toThrow(
			"userinfo response includes claims with names that are not known.",
		);
	});
});

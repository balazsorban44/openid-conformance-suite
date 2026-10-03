import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import type { ParsedJwt } from "../suite/jose.ts";
import { useTestLog } from "../suite/testing.ts";
import { compareIdTokenClaims } from "./id-token.ts";
import { checkTokenEndpointCacheHeaders, ensureAccessTokenValuesAreDifferent } from "./refresh-token.ts";
import type { TokenResponse } from "./token.ts";

const t = useTestLog();

const response = (headers: Record<string, string | string[]>): TokenResponse => ({
	status: 200,
	endpoint_name: "https://op.example/token",
	headers,
	body: "{}",
	json: {},
});

const idToken = (claims: Record<string, unknown>): ParsedJwt => ({ value: "x", header: {}, claims });
const base = { iss: "https://op.example", sub: "u", aud: "c1", iat: 100, auth_time: 50 };

describe("cache headers of the token response (RFC6749-5.1)", () => {
	test("no-store may be one of several cache-control directives or header values", () => {
		checkTokenEndpointCacheHeaders(response({ "cache-control": "private, no-store" }), "RFC6749-5.1");
		checkTokenEndpointCacheHeaders(response({ "cache-control": ["private", "no-store"] }), "RFC6749-5.1");
		expect(t.entries().every((e) => e["result"] === "SUCCESS")).toBe(true);
	});

	test("no cache-control header and a header without no-store fail", () => {
		expect(() => checkTokenEndpointCacheHeaders(response({}))).toThrow(ConditionFailed);
		expect(() => checkTokenEndpointCacheHeaders(response({ "cache-control": "no-cache" }))).toThrow(ConditionFailed);
		expect(t.entries().map((e) => e["msg"])).toEqual([
			"token endpoint response does not contain 'cache-control' header",
			"'cache-control' header in token endpoint response does not contain expected value.",
		]);
	});
});

describe("ensureAccessTokenValuesAreDifferent", () => {
	test("the refreshed access token must not be the first one", () => {
		const first = { value: "a", type: "Bearer" };
		expect(() => ensureAccessTokenValuesAreDifferent(first, first)).toThrow(ConditionFailed);
		ensureAccessTokenValuesAreDifferent(first, { value: "b", type: "Bearer" });
	});
});

describe("compareIdTokenClaims (OIDCC-12.2)", () => {
	const refreshed = { ...base, iat: 200 };

	test("same iss, sub, aud, auth_time and a later iat pass", () => {
		compareIdTokenClaims(idToken(base), idToken(refreshed), "OIDCC-12.2");
		expect(t.entries().at(-1)).toMatchObject({ result: "SUCCESS", msg: "Validated id token claims successfully" });
	});

	test.each([
		[
			"the same iat",
			{ ...base },
			"iat for the second id token MUST represent the time that the new ID Token is issued",
		],
		["a different sub", { ...refreshed, sub: "other" }, "Claim values are not the same"],
		["another audience", { ...refreshed, aud: "c2" }, "aud Claim Value MUST be the same"],
		["another auth_time", { ...refreshed, auth_time: 60 }, "auth_time claims are not the same"],
		["an azp the first token did not have", { ...refreshed, azp: "c1" }, "Second id token cannot contain an azp claim"],
	])("%s fails", (_name, second, message) => {
		expect(() => compareIdTokenClaims(idToken(base), idToken(second))).toThrow(ConditionFailed);
		expect(String(t.entries().at(-1)?.["msg"])).toContain(message);
	});

	test("array audiences are compared as sets", () => {
		compareIdTokenClaims(idToken({ ...base, aud: ["a", "b"] }), idToken({ ...refreshed, aud: ["b", "a"] }));
		expect(() =>
			compareIdTokenClaims(idToken({ ...base, aud: ["a", "b"] }), idToken({ ...refreshed, aud: ["a"] })),
		).toThrow(ConditionFailed);
	});
});

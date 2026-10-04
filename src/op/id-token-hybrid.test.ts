import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import type { ParsedJwt } from "../suite/jose.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	checkAuthorizationEndpointHashes,
	ensureIdTokenContainsName,
	verifyIdTokenSubConsistentHybridFlow,
	verifyScopesReturnedInAuthorizationEndpointIdToken,
} from "./id-token.ts";

const t = useTestLog();
const idToken = (claims: Record<string, unknown>): ParsedJwt => ({ value: "x", header: { alg: "RS256" }, claims });
const last = () => t.entries().at(-1);
/** the left half of the SHA-256 of `s`, base64url (OIDCC 3.3.2.11 for RS256) */
const halfHash = (s: string) => createHash("sha256").update(s).digest().subarray(0, 16).toString("base64url");

describe("the id_tokens of a hybrid flow", () => {
	test("the authorization endpoint's and the token endpoint's id_token must have the same sub", () => {
		verifyIdTokenSubConsistentHybridFlow(idToken({ sub: "a" }), idToken({ sub: "a" }), "OIDCC-2");
		expect(last()).toMatchObject({
			src: "VerifyIdTokenSubConsistentHybridFlow",
			result: "SUCCESS",
			msg: "authorization endpoint and token endpoint id_token have same sub",
			sub_auth_endpoint: "a",
			sub_token_endpoint: "a",
			requirements: ["OIDCC-2"],
		});
		expect(() => verifyIdTokenSubConsistentHybridFlow(idToken({ sub: "a" }), idToken({ sub: "b" }))).toThrow(
			ConditionFailed,
		);
		expect(last()).toMatchObject({
			result: "FAILURE",
			msg: '"sub" in authorization endpoint id_token doesn\'t match with "sub" in token endpoint id_token',
		});
	});
});

describe("at_hash and c_hash of an id_token from the authorization endpoint", () => {
	const accessToken = { value: "at-1", type: "Bearer" };

	test("are required with the access token / code returned alongside and validated", () => {
		const parsed = idToken({ at_hash: halfHash("at-1"), c_hash: halfHash("code-1") });
		checkAuthorizationEndpointHashes(parsed, "code id_token token", accessToken, "code-1");
		expect(t.entries().map((e) => [e.src, e["result"]])).toEqual([
			["ExtractAtHash", "SUCCESS"],
			["ValidateAtHash", "SUCCESS"],
			["ExtractCHash", "SUCCESS"],
			["ValidateCHash", "SUCCESS"],
		]);
	});

	test("a missing at_hash fails when an access token was returned, a missing c_hash is only INFO without a code", () => {
		checkAuthorizationEndpointHashes(idToken({}), "id_token token", accessToken, null);
		expect(t.entries().map((e) => [e.src, e["result"], e["msg"]])).toEqual([
			["ExtractAtHash", "FAILURE", "Couldn't find at_hash in ID token"],
			["ValidateAtHash", "INFO", "Skipped evaluation due to missing required object: at_hash"],
			["ExtractCHash", "INFO", "Couldn't find c_hash in ID token"],
			["ValidateCHash", "INFO", "Skipped evaluation due to missing required object: c_hash"],
		]);
	});

	test("a wrong c_hash fails; one without a code to check it against fails with upstream's message", () => {
		checkAuthorizationEndpointHashes(idToken({ c_hash: halfHash("other") }), "code id_token", null, "code-1");
		expect(t.entries().find((e) => e.src === "ValidateCHash")).toMatchObject({
			result: "FAILURE",
			msg: "Invalid c_hash in token",
			unhashed_value: "code-1",
		});
		checkAuthorizationEndpointHashes(idToken({ c_hash: halfHash("code-1") }), "id_token", null, null);
		expect(last()).toMatchObject({
			src: "ValidateCHash",
			result: "FAILURE",
			msg: "Could not find authorization_endpoint_response.code",
		});
	});
});

describe("claims in the id_token of response_type=id_token", () => {
	test("the scopes' claims must be in the authorization endpoint's id_token", () => {
		const request = { params: { scope: "openid email" } };
		verifyScopesReturnedInAuthorizationEndpointIdToken(
			idToken({ sub: "a", email: "a@example.com", email_verified: true }),
			request,
			"OIDCC-5.4",
		);
		expect(last()).toMatchObject({
			src: "VerifyScopesReturnedInAuthorizationEndpointIdToken",
			result: "SUCCESS",
			msg: "'claims' in authorization_endpoint_id_token contains all scope items of scope in authorization request (corresponds to scope standard claims)",
		});
		expect(() =>
			verifyScopesReturnedInAuthorizationEndpointIdToken(idToken({ sub: "a", email: "a@example.com" }), request),
		).toThrow(ConditionFailed);
		expect(last()).toMatchObject({
			msg: "'claims' in authorization_endpoint_id_token doesn't contain all scope items of scope in authorization request(corresponds to scope standard claims)",
			missing_items: ["email_verified"],
		});
	});

	test("an essential name claim must be in the id_token", () => {
		ensureIdTokenContainsName(idToken({ name: "Jane" }));
		expect(last()).toMatchObject({ result: "SUCCESS", msg: "Found name in id_token", name: "Jane" });
		expect(() => ensureIdTokenContainsName(idToken({ name: "" }))).toThrow(ConditionFailed);
		expect(last()).toMatchObject({ result: "FAILURE", msg: "name not found in id_token" });
	});
});

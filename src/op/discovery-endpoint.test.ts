import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	checkDiscEndpointAllEndpointsAreHttps,
	checkDiscEndpointRequestUriParameterSupported,
	oidccCheckIdTokenSigningAlgValuesSupportedAlgNone,
} from "./discovery.ts";
import {
	checkDiscEndpointIssuer,
	ensureServerConfigurationCodeChallengeMethodsSupportedIsAnArray,
	oidccCheckDiscEndpointResponseTypesSupportedDynamic,
} from "./discovery-endpoint.ts";

const t = useTestLog();

describe("checkDiscEndpointIssuer", () => {
	const config = { server: { discoveryUrl: "https://op.example/path/.well-known/openid-configuration" } };

	test("the issuer is the discovery URL without the well-known suffix, a trailing slash is ignored", () => {
		checkDiscEndpointIssuer({ issuer: "https://op.example/path" }, config, "OIDCD-4.3");
		checkDiscEndpointIssuer({ issuer: "https://op.example/path/" }, config, "OIDCD-4.3");
		expect(t.entries().map((e) => [e.src, e["result"], e["msg"]])).toEqual([
			["CheckDiscEndpointIssuer", "SUCCESS", "issuer is consistent with the discovery endpoint"],
			["CheckDiscEndpointIssuer", "SUCCESS", "issuer is consistent with the discovery endpoint"],
		]);
	});

	test("a different issuer fails", () => {
		expect(() => checkDiscEndpointIssuer({ issuer: "https://evil.example" }, config)).toThrow(ConditionFailed);
		expect(t.entries().at(-1)).toMatchObject({
			result: "FAILURE",
			discovery_url: "https://op.example/path/",
			issuer: "https://evil.example",
		});
	});

	test("a missing issuer fails", () => {
		expect(() => checkDiscEndpointIssuer({}, config)).toThrow("issuer is missing from discovery endpoint document");
	});
});

describe("response types are compared as sets of values", () => {
	test("the dynamic profile needs code, id_token and token id_token, in any order", () => {
		oidccCheckDiscEndpointResponseTypesSupportedDynamic({
			response_types_supported: ["id_token token", "code", "id_token"],
		});
		expect(t.entries().at(-1)).toMatchObject({ result: "SUCCESS", minimum_matches_required: 3 });
	});

	test("a missing one fails with upstream's message", () => {
		expect(() =>
			oidccCheckDiscEndpointResponseTypesSupportedDynamic({ response_types_supported: ["code", "id_token"] }),
		).toThrow(ConditionFailed);
		expect(t.entries().at(-1)).toMatchObject({
			msg: "The server does not support all of the mandatory to implement response_types for dynamic OpenID Providers.",
		});
	});
});

describe("defaults", () => {
	test("request_uri_parameter_supported defaults to true", () => {
		checkDiscEndpointRequestUriParameterSupported({});
		expect(t.entries().at(-1)).toMatchObject({ result: "SUCCESS", request_uri_parameter_supported: null });
	});

	test("an absent or empty code_challenge_methods_supported is fine, a wrong value is not", () => {
		ensureServerConfigurationCodeChallengeMethodsSupportedIsAnArray({});
		ensureServerConfigurationCodeChallengeMethodsSupportedIsAnArray({ code_challenge_methods_supported: [] });
		expect(() =>
			ensureServerConfigurationCodeChallengeMethodsSupportedIsAnArray({ code_challenge_methods_supported: ["S512"] }),
		).toThrow(ConditionFailed);
	});

	test("every *_endpoint must be https", () => {
		expect(() =>
			checkDiscEndpointAllEndpointsAreHttps({
				authorization_endpoint: "https://op.example/auth",
				token_endpoint: "http://op.example/token",
			}),
		).toThrow(ConditionFailed);
		expect(t.entries().map((e) => [e["result"], e["msg"]])).toEqual([
			["SUCCESS", "authorization_endpoint"],
			["FAILURE", "token_endpoint must use the https scheme"],
		]);
	});
});

describe("oidccCheckIdTokenSigningAlgValuesSupportedAlgNone", () => {
	test("none must be listed", () => {
		expect(oidccCheckIdTokenSigningAlgValuesSupportedAlgNone({ id_token_signing_alg_values_supported: ["none"] })).toBe(
			true,
		);
		expect(() =>
			oidccCheckIdTokenSigningAlgValuesSupportedAlgNone({ id_token_signing_alg_values_supported: ["RS256"] }),
		).toThrow("'id_token_signing_alg_values_supported' doesn't contain 'none' algorithm'");
	});
});

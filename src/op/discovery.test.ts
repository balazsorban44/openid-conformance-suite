import { http, HttpResponse } from "msw";
import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { useMswServer, useTestLog } from "../suite/testing.ts";
import {
	checkServerConfiguration,
	ensureServerConfigurationSupportsClientSecretBasic,
	getDynamicServerConfiguration,
} from "./discovery.ts";
import { loadServerKeys } from "./jwks.ts";

const t = useTestLog();
const server = useMswServer();

const metadata = {
	issuer: "https://op.example",
	authorization_endpoint: "https://op.example/auth",
	token_endpoint: "https://op.example/token",
	jwks_uri: "https://op.example/jwks",
};

describe("getDynamicServerConfiguration", () => {
	test("fetches server.discoveryUrl and logs the document", async () => {
		server.use(http.get("https://op.example/.well-known/openid-configuration", () => HttpResponse.json(metadata)));
		const { metadata: m } = await getDynamicServerConfiguration({
			server: { discoveryUrl: "https://op.example/.well-known/openid-configuration" },
		});
		expect(m).toEqual(metadata);
		expect(t.entries().map((e) => [e.src, e["msg"], e["result"]])).toEqual([
			["GetDynamicServerConfiguration", "HTTP request", undefined],
			["GetDynamicServerConfiguration", "HTTP response", undefined],
			["GetDynamicServerConfiguration", "Successfully parsed server configuration", "SUCCESS"],
		]);
		expect(t.entries()[2]).toMatchObject(metadata);
	});

	test("discoveryIssuer + /.well-known/openid-configuration", async () => {
		server.use(http.get("https://op.example/.well-known/openid-configuration", () => HttpResponse.json(metadata)));
		await getDynamicServerConfiguration({ server: { discoveryIssuer: "https://op.example" } });
		expect(t.entries()[0]["request_uri"]).toBe("https://op.example/.well-known/openid-configuration");
	});

	test("an error status fails with upstream's message", async () => {
		server.use(
			http.get("https://op.example/.well-known/openid-configuration", () => HttpResponse.text("gone", { status: 404 })),
		);
		await expect(
			getDynamicServerConfiguration({
				server: { discoveryUrl: "https://op.example/.well-known/openid-configuration" },
			}),
		).rejects.toThrow(ConditionFailed);
		expect(t.entries().at(-1)).toMatchObject({
			src: "GetDynamicServerConfiguration",
			msg: "Unable to fetch server configuration from https://op.example/.well-known/openid-configuration",
			result: "FAILURE",
			error: "404 Not Found: gone",
		});
	});

	test("a static issuer in the configuration is a configuration error", async () => {
		await expect(getDynamicServerConfiguration({ server: { issuer: "https://op.example" } })).rejects.toThrow(
			"GetDynamicServerConfiguration: Test set to use dynamic server configuration but test configuration contains static server configuration",
		);
	});
});

describe("server configuration checks", () => {
	test("CheckServerConfiguration names the first missing endpoint", () => {
		expect(() => checkServerConfiguration({ ...metadata, token_endpoint: undefined })).toThrow(ConditionFailed);
		expect(t.entries()[0]).toMatchObject({ msg: "Couldn't find required component", required: "token_endpoint" });
		checkServerConfiguration(metadata);
		expect(t.entries()[1]).toMatchObject({ msg: "Found required server configuration keys", result: "SUCCESS" });
	});

	test("client_secret_basic is the default when token_endpoint_auth_methods_supported is absent", () => {
		ensureServerConfigurationSupportsClientSecretBasic(metadata);
		expect(() =>
			ensureServerConfigurationSupportsClientSecretBasic({
				...metadata,
				token_endpoint_auth_methods_supported: ["private_key_jwt"],
			}),
		).toThrow(
			"server discovery document contains token_endpoint_auth_methods_supported which does not contain client_secret_basic",
		);
	});
});

describe("loadServerKeys", () => {
	test("fetches the JWKS and runs upstream's checks in order", async () => {
		const jwks = {
			keys: [
				{
					kty: "EC",
					crv: "P-256",
					kid: "k1",
					x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
					y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
					use: "sig",
				},
			],
		};
		server.use(http.get("https://op.example/jwks", () => HttpResponse.json(jwks)));
		expect(await loadServerKeys(metadata)).toEqual(jwks);
		expect(t.entries().map((e) => [e.src, e["result"] ?? null, e["requirements"] ?? null])).toEqual([
			["FetchServerKeys", null, null],
			["FetchServerKeys", null, null],
			["FetchServerKeys", null, null],
			["FetchServerKeys", null, null],
			["FetchServerKeys", "SUCCESS", null],
			["CheckServerKeysIsValid", "SUCCESS", null],
			["-START-BLOCK-", null, null],
			["MapJwksToValidationLocation", "SUCCESS", null],
			["EnsureJwksHasNoPrivateOrSymmetricKeyMaterial", "SUCCESS", ["RFC7517-1.1"]],
			["ValidateJwksStructure", "SUCCESS", ["RFC7517-1.1"]],
			["ParseUsableJwksKeys", "SUCCESS", ["RFC7517-1.1"]],
			["WarnOnUnusableJwksKeys", "SUCCESS", ["RFC7517-1.1"]],
			["CheckForKeyIdInServerJWKs", "SUCCESS", ["OIDCC-10.1"]],
			["CheckDistinctKeyIdValueInServerJWKs", "SUCCESS", ["RFC7517-4.5"]],
		]);
	});

	test("a key without kid, a duplicate kid and private key material are failures but the test continues", async () => {
		const key = { kty: "oct", k: "c2VjcmV0" };
		server.use(
			http.get("https://op.example/jwks", () =>
				HttpResponse.json({ keys: [key, { ...key, kid: "a" }, { ...key, kid: "a" }] }),
			),
		);
		await loadServerKeys(metadata);
		const failures = t
			.entries()
			.filter((e) => e["result"] === "FAILURE")
			.map((e) => e.src);
		expect(failures).toEqual([
			"EnsureJwksHasNoPrivateOrSymmetricKeyMaterial",
			"CheckForKeyIdInServerJWKs",
			"CheckDistinctKeyIdValueInServerJWKs",
		]);
	});
});

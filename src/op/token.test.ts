import { http, HttpResponse } from "msw";
import { describe, expect, test } from "vitest";
import { useMswServer, useTestLog } from "../suite/testing.ts";
import type { OpVariant } from "./op.ts";
import type { RegisteredClient } from "./registration.ts";
import {
	callTokenEndpoint,
	checkAuthorizationCodeReuseResponse,
	createAuthorizationCodeRequest,
	formUrlEncode,
	requestAuthorizationCode,
} from "./token.ts";

const t = useTestLog();
const server = useMswServer();

const op = {
	metadata: { issuer: "https://op.example", token_endpoint: "https://op.example/token" },
	redirectUri: "https://suite.example/test/a/x/callback",
	variant: { client_auth_type: "client_secret_basic" } as OpVariant,
};
const client: RegisteredClient = { client: { client_id: "c 1", client_secret: "s:é" }, keys: null, dynamic: false };

describe("authorization code request", () => {
	test("client_secret_basic: form-urlencoded id and secret in the Authorization header (RFC6749-2.3.1)", async () => {
		let body = "";
		let authorization: string | null = null;
		server.use(
			http.post("https://op.example/token", async ({ request }) => {
				body = await request.text();
				authorization = request.headers.get("authorization");
				return HttpResponse.json({ error: "invalid_grant" }, { status: 400 });
			}),
		);
		const req = await createAuthorizationCodeRequest(op, client, "the-code");
		const res = await callTokenEndpoint(op, req);

		expect(authorization).toBe(
			"Basic " + Buffer.from(`${formUrlEncode("c 1")}:${formUrlEncode("s:é")}`).toString("base64"),
		);
		expect(formUrlEncode("c 1")).toBe("c+1");
		expect(body).toBe(
			"grant_type=authorization_code&code=the-code&redirect_uri=https%3A%2F%2Fsuite.example%2Ftest%2Fa%2Fx%2Fcallback",
		);
		expect(res.status).toBe(400);
		expect(res.json).toEqual({ error: "invalid_grant" });
		expect(t.entries().map((e) => [e.src, e["msg"], e["result"]])).toEqual([
			["CreateTokenEndpointRequestForAuthorizationCodeGrant", "Created token endpoint request", "SUCCESS"],
			["AddBasicAuthClientSecretToRequest", "Added basic authorization header", "SUCCESS"],
			["CallTokenEndpointAndReturnFullResponse", "HTTP request", undefined],
			["CallTokenEndpointAndReturnFullResponse", "HTTP response", undefined],
			["CallTokenEndpointAndReturnFullResponse", "Parsed token endpoint response", "SUCCESS"],
		]);
		// upstream records the endpoint URI as the endpoint name of the token endpoint response
		expect(t.entries()[4]).toMatchObject({ status: 400, endpoint_name: "https://op.example/token" });
	});

	test("a successful response without an id_token stops the flow at ExtractIdTokenFromTokenResponse", async () => {
		server.use(
			http.post("https://op.example/token", () =>
				HttpResponse.json({ access_token: "at", token_type: "Bearer", expires_in: 60 }),
			),
		);
		const req = await createAuthorizationCodeRequest(op, client, "code");
		await expect(requestAuthorizationCode(op, client, req)).rejects.toThrow(
			"ExtractIdTokenFromTokenResponse: Couldn't find id_token in token_endpoint_response",
		);
		const results = Object.fromEntries(
			t
				.entries()
				.filter((e) => e["result"])
				.map((e) => [e.src, e["result"]]),
		);
		expect(results).toMatchObject({
			CheckTokenEndpointHttpStatus200: "SUCCESS",
			CheckIfTokenEndpointResponseError: "SUCCESS",
			CheckForAccessTokenValue: "SUCCESS",
			ExtractAccessTokenFromTokenResponse: "SUCCESS",
			ExtractExpiresInFromTokenEndpointResponse: "SUCCESS",
			ValidateExpiresIn: "SUCCESS",
			// optional: recorded as INFO, the flow continues
			CheckForRefreshTokenValue: "INFO",
			// a static client without keys: skipped
			ValidateIdTokenFromTokenResponseEncryption: "INFO",
			ExtractIdTokenFromTokenResponse: "FAILURE",
		});
	});
});

describe("authorization code reuse", () => {
	test("invalid_grant with status 400 and a JSON body passes every check", async () => {
		server.use(
			http.post("https://op.example/token", () =>
				HttpResponse.json({ error: "invalid_grant", error_description: "grant request is invalid" }, { status: 400 }),
			),
		);
		checkAuthorizationCodeReuseResponse(await callTokenEndpoint(op, { form: { code: "c" }, headers: {} }));
		const checks = t.entries().filter((e) => e["result"]);
		expect(checks.map((e) => [e.src, e["result"]])).toEqual([
			["CallTokenEndpointAndReturnFullResponse", "SUCCESS"],
			["CheckTokenEndpointHttpStatus400", "SUCCESS"],
			["CheckTokenEndpointReturnedJsonContentType", "SUCCESS"],
			["CheckErrorFromTokenEndpointResponseErrorInvalidGrant", "SUCCESS"],
			["ValidateErrorFromTokenEndpointResponseError", "SUCCESS"],
			["CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB", "SUCCESS"],
			["ValidateErrorDescriptionFromTokenEndpointResponseError", "SUCCESS"],
			["ValidateErrorUriFromTokenEndpointResponseError", "SUCCESS"],
		]);
	});

	test("a second successful exchange is a warning (ServerAllowedReusingAuthorizationCode)", async () => {
		server.use(http.post("https://op.example/token", () => HttpResponse.json({ access_token: "again" })));
		checkAuthorizationCodeReuseResponse(await callTokenEndpoint(op, { form: { code: "c" }, headers: {} }));
		expect(t.entries().at(-1)).toMatchObject({
			src: "ServerAllowedReusingAuthorizationCode",
			result: "WARNING",
			msg: "Server has incorrectly allowed a second use of an authorization code; an authorization code is expected to be single use.",
		});
	});
});

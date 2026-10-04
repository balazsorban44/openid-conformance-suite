import { createHash } from "node:crypto";
import { createLocalJWKSet, decodeJwt, jwtVerify, type JSONWebKeySet } from "jose";
import { afterEach, describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { startServer, type TestServer } from "../suite/server.ts";
import { useTestLog } from "../suite/testing.ts";
import * as idToken from "./id-token.ts";
import { failTest, startEmulatedOp, type EmulatedOpOptions, type RpVariant } from "./op.ts";

const t = useTestLog("oidcc-client-test");

const variant: RpVariant = {
	client_registration: "dynamic_client",
	client_auth_type: "client_secret_basic",
	response_type: "code",
	response_mode: "default",
	request_type: "plain_http_request",
};

let server: TestServer | null = null;
afterEach(async () => {
	await server?.close();
	server = null;
});

async function start(options: EmulatedOpOptions = {}) {
	server = await startServer({ log: t.log, testName: "oidcc-client-test", alias: "rp" });
	return startEmulatedOp(server, { testName: "oidcc-client-test", variant, config: {} }, options);
}

/** What an RP does: register, send the user to the authorization endpoint, exchange the code */
async function login(issuer: string, opts: { clientId?: string } = {}) {
	const reg = await fetch(issuer + "register", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			redirect_uris: ["https://rp.example/cb"],
			token_endpoint_auth_method: "client_secret_basic",
		}),
	});
	const client = (await reg.json()) as { client_id: string; client_secret: string };
	const authorize = new URL(issuer + "authorize");
	authorize.search = new URLSearchParams({
		client_id: opts.clientId ?? client.client_id,
		redirect_uri: "https://rp.example/cb",
		response_type: "code",
		scope: "openid email",
		state: "s1",
		nonce: "n-0S6_WzA2Mj",
	}).toString();
	const authz = await fetch(authorize, { redirect: "manual" });
	const location = authz.headers.get("location");
	const code = location ? new URL(location).searchParams.get("code") : null;
	const token = code
		? await fetch(issuer + "token", {
				method: "POST",
				headers: {
					authorization:
						"Basic " +
						Buffer.from(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`).toString(
							"base64",
						),
				},
				body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: "https://rp.example/cb" }),
			})
		: null;
	return { reg, client, authz, location, token };
}

describe("the emulated OP", () => {
	test("serves the code flow and reports each request in order; the id_token is signed with a published key", async () => {
		const op = await start();
		const flow = login(op.issuer);

		const registration = await op.expect("registration");
		const authorization = await op.expect("authorization");
		const token = await op.expect("token");
		const { reg, location } = await flow;

		expect(reg.status).toBe(201);
		expect(registration.client["client_secret"]).toMatch(/^secret_/);
		expect(registration.client["id_token_signed_response_alg"]).toBe(op.signingAlg);
		expect(authorization.authorization.scope).toBe("openid email");
		expect(location).toBe(`https://rp.example/cb?state=s1&code=${authorization.authorization.code}`);

		const jwks = (await (await fetch(op.issuer + "jwks")).json()) as JSONWebKeySet;
		const idTokenValue = String(token.response["id_token"]);
		const { payload } = await jwtVerify(idTokenValue, createLocalJWKSet(jwks), {
			issuer: op.issuer,
			audience: registration.client.client_id,
		});
		expect(payload["nonce"]).toBe("n-0S6_WzA2Mj");
		// at_hash: left half of the SHA-256 of the access token (OIDCC 3.3.2.11, RS256 by default)
		const digest = createHash("sha256").update(String(token.response["access_token"])).digest();
		expect(payload["at_hash"]).toBe(digest.subarray(0, 16).toString("base64url"));
		expect(token.response["scope"]).toBe("openid email");
	});

	test("a failing check ends the test: the request gets an error and expect() rejects with the failure", async () => {
		const op = await start();
		const flow = login(op.issuer, { clientId: "someone-else" });

		await op.expect("registration");
		const failure = await op.expect("authorization").catch((e: unknown) => e);
		const { authz } = await flow;

		expect(failure).toBeInstanceOf(ConditionFailed);
		expect((failure as ConditionFailed).condition).toBe("EnsureMatchingClientId");
		expect(authz.status).toBe(500);
		expect(
			t
				.entries()
				.filter((e) => e["result"] === "FAILURE")
				.map((e) => e.src),
		).toEqual(["EnsureMatchingClientId"]);
		// later requests are refused too
		await expect(op.expect("token")).rejects.toBe(failure);
	});

	test("the module's id_token change is applied after the claims are generated", async () => {
		const op = await start({ idTokenClaims: (claims) => idToken.addInvalidAudValueToIdToken(claims, "OIDCC-3.1.3.7") });
		const flow = login(op.issuer);
		const { client } = await op.expect("registration");
		const token = await op.expect("token");
		await flow;

		expect(decodeJwt(String(token.response["id_token"])).aud).toBe(client.client_id + "1");
		const sources = t.entries().map((e) => e.src);
		expect(sources.indexOf("AddInvalidAudValueToIdToken")).toBe(sources.indexOf("GenerateIdTokenClaims") + 1);
	});

	test("a module's nonce extraction and at_hash step replace the default ones", async () => {
		const calls: string[] = [];
		const op = await start({
			extractNonce: (params) => {
				calls.push("extractNonce");
				return params["nonce"] as string;
			},
			addAtHashToIdToken: (claims, atHash) => {
				calls.push(`addAtHashToIdToken ${atHash == null ? "null" : "at_hash"}`);
				claims["at_hash"] = "replaced";
			},
		});
		const flow = login(op.issuer);
		await op.expect("authorization");
		const token = await op.expect("token");
		await flow;

		expect(calls).toEqual(["extractNonce", "addAtHashToIdToken at_hash"]);
		const payload = decodeJwt(String(token.response["id_token"]));
		expect(payload["nonce"]).toBe("n-0S6_WzA2Mj");
		expect(payload["at_hash"]).toBe("replaced");
		const sources = t.entries().map((e) => e.src);
		expect(sources).not.toContain("ExtractNonceFromAuthorizationRequest");
		expect(sources).not.toContain("AddAtHashToIdTokenClaims");
	});

	test("waitFor() resolves null once the RP finished; expect() then rejects", async () => {
		const op = await start();
		const optional = op.waitFor("userinfo", 30);
		const required = op.expect("token", { timeoutSeconds: 30 });
		op.rpFinished();

		await expect(optional).resolves.toBeNull();
		await expect(required).rejects.toThrow("The relying party under test finished without sending a token request");
	});

	test("a request the module refuses fails the test before anything is checked", async () => {
		const op = await start({ onUserinfoRequest: () => failTest("Client has incorrectly called userinfo_endpoint.") });
		const waiting = op.waitFor("userinfo", 30).catch((e: unknown) => e);
		const res = await fetch(op.issuer + "userinfo", { headers: { authorization: "Bearer x" } });

		expect(String(await waiting)).toBe(
			"ConditionFailed: oidcc-client-test: Client has incorrectly called userinfo_endpoint.",
		);
		expect(res.status).toBe(500);
		const logged = t.entries().filter((e) => e.src === "oidcc-client-test" && e["result"] === "FAILURE");
		expect(logged.map((e) => e["msg"])).toEqual(["Client has incorrectly called userinfo_endpoint."]);
		expect(t.entries().some((e) => e.src === "-START-BLOCK-" && e["msg"] === "Userinfo endpoint")).toBe(false);
	});
});

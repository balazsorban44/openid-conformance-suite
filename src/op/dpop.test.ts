import { http, HttpResponse } from "msw";
import { beforeAll, describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { generateJwkForAlg, type JWK } from "../suite/jose.ts";
import { useMswServer, useTestLog } from "../suite/testing.ts";
import {
	callProtectedResourceAllowingDpopNonceError,
	callTokenEndpointAllowingDpopNonceError,
	checkTokenTypeIsDpop,
	createTokenEndpointDpopSteps,
	dpopNonceResponseHeader,
	generateDpopKey,
	hasUseDpopNonceChallenge,
	newDpopState,
	parseWwwAuthenticate,
	type DpopClient,
} from "./dpop.ts";
import type { TokenRequest, TokenResponse } from "./token.ts";

const t = useTestLog();
const server = useMswServer();

const metadata = {
	issuer: "https://op.example",
	token_endpoint: "https://op.example/token",
	dpop_signing_alg_values_supported: ["ES256", "PS256"],
};
let key: JWK;
beforeAll(async () => {
	key = await generateJwkForAlg("ES256");
});

function client(): DpopClient {
	return { client: { client_id: "c1", dpop_signing_alg: "ES256" }, dpop: { ...newDpopState(), key } };
}

function decode(jwt: string): { header: Record<string, unknown>; claims: Record<string, unknown> } {
	const [h, p] = jwt.split(".");
	return {
		header: JSON.parse(Buffer.from(h, "base64url").toString()),
		claims: JSON.parse(Buffer.from(p, "base64url").toString()),
	};
}

describe("GenerateDpopKey", () => {
	test("the client's dpop_signing_alg when the OP supports it, with a thumbprint kid", async () => {
		const c = { client: { client_id: "c1", dpop_signing_alg: "ES256" }, dpop: newDpopState() };
		const generated = await generateDpopKey(metadata, c);
		expect(generated).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig" });
		expect(typeof generated["kid"]).toBe("string");
		expect(c.dpop.key).toBe(generated);
		expect(t.entries().at(-1)).toMatchObject({ src: "GenerateDpopKey", result: "SUCCESS", msg: "Generated dPOP JWKs" });
	});

	test("falls back to the first algorithm the OP lists when the preferred one is not supported", async () => {
		const c = { client: { client_id: "c1", dpop_signing_alg: "PS256" }, dpop: newDpopState() };
		const generated = await generateDpopKey({ ...metadata, dpop_signing_alg_values_supported: ["ES256"] }, c);
		expect(generated["alg"]).toBe("ES256");
	});
});

describe("DPoP-Nonce response header (RFC9449-8)", () => {
	test("none, one, several, empty and invalid", () => {
		expect(dpopNonceResponseHeader({})).toEqual({ nonce: null, violation: null });
		expect(dpopNonceResponseHeader({ "dpop-nonce": "abc-123" })).toEqual({ nonce: "abc-123", violation: null });
		expect(dpopNonceResponseHeader({ "dpop-nonce": ["a", "b"] }).violation).toMatch(
			/contains 2 DPoP-Nonce headers, but RFC9449 section 8 says there MUST NOT be more than one/,
		);
		expect(dpopNonceResponseHeader({ "dpop-nonce": "" }).violation).toMatch(/is empty/);
		expect(dpopNonceResponseHeader({ "dpop-nonce": 'a"b' }).violation).toMatch(/characters that are not allowed/);
	});

	test("the WWW-Authenticate challenge of a resource server", () => {
		const parsed = parseWwwAuthenticate('Bearer realm="api", DPoP error="use_dpop_nonce", error_description="x, y"');
		expect([...parsed.keys()]).toEqual(["Bearer", "DPoP"]);
		expect(parsed.get("DPoP")?.get("error")).toBe("use_dpop_nonce");
		expect(parsed.get("DPoP")?.get("error_description")).toBe("x, y");
		expect(hasUseDpopNonceChallenge({ "www-authenticate": 'DPoP error="use_dpop_nonce"' })).toBe(true);
		// the scheme is matched case-insensitively (RFC 7235), the parameter name as upstream does: exactly
		expect(hasUseDpopNonceChallenge({ "www-authenticate": 'dpop error="use_dpop_nonce"' })).toBe(true);
		expect(hasUseDpopNonceChallenge({ "www-authenticate": 'DPoP ERROR="use_dpop_nonce"' })).toBe(false);
		expect(hasUseDpopNonceChallenge({ "www-authenticate": 'Bearer error="invalid_token"' })).toBe(false);
		expect(hasUseDpopNonceChallenge({})).toBe(false);
	});
});

describe("the token endpoint's use_dpop_nonce error (RFC9449-8.2)", () => {
	test("the proof is signed with the client's key; the retry carries the supplied nonce", async () => {
		const proofs: string[] = [];
		server.use(
			http.post("https://op.example/token", ({ request }) => {
				proofs.push(request.headers.get("dpop") ?? "");
				if (proofs.length === 1) {
					return HttpResponse.json(
						{ error: "use_dpop_nonce" },
						{ status: 400, headers: { "DPoP-Nonce": "server-nonce-1" } },
					);
				}
				return HttpResponse.json({ access_token: "at", token_type: "DPoP" });
			}),
		);
		const c = client();
		const req: TokenRequest = { form: { grant_type: "authorization_code", code: "x" }, headers: {} };

		await createTokenEndpointDpopSteps(metadata, c, req);
		const first = await callTokenEndpointAllowingDpopNonceError({ metadata }, req, c.dpop, "RFC9449-8.2");
		expect(first.nonceError).toBe("server-nonce-1");
		expect(c.dpop.authorizationServerNonce).toBe("server-nonce-1");
		expect(first.response.status).toBe(400);

		await createTokenEndpointDpopSteps(metadata, c, req);
		const second = await callTokenEndpointAllowingDpopNonceError({ metadata }, req, c.dpop);
		expect(second.nonceError).toBeNull();
		expect(second.response.json).toEqual({ access_token: "at", token_type: "DPoP" });

		const [p1, p2] = proofs.map(decode);
		expect(p1.header).toMatchObject({ typ: "dpop+jwt", alg: "ES256", jwk: { kty: "EC", crv: "P-256" } });
		expect(p1.header["jwk"]).not.toHaveProperty("d");
		expect(p1.claims).toMatchObject({ htm: "POST", htu: "https://op.example/token" });
		expect(p1.claims).not.toHaveProperty("nonce");
		expect(p2.claims["nonce"]).toBe("server-nonce-1");
		expect(p2.claims["jti"]).not.toBe(p1.claims["jti"]);

		const results = t.entries().map((e) => [e.src, e["result"], e["msg"]]);
		expect(results).toContainEqual([
			"SetDpopProofNonceForAuthorizationServer",
			"INFO",
			"authorization_server_dpop_nonce not found",
		]);
		expect(results).toContainEqual([
			"CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse",
			"SUCCESS",
			"Parsed token endpoint response - DPoP nonce supplied",
		]);
		expect(results).toContainEqual([
			"SetDpopProofNonceForAuthorizationServer",
			"SUCCESS",
			"Added nonce to DPoP proof claims",
		]);
		expect(results.at(-1)).toEqual([
			"CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse",
			"SUCCESS",
			"Parsed token endpoint response - no DPoP nonce supplied",
		]);
	});

	test("a use_dpop_nonce error without a DPoP-Nonce header is a failure", async () => {
		server.use(
			http.post("https://op.example/token", () => HttpResponse.json({ error: "use_dpop_nonce" }, { status: 400 })),
		);
		const c = client();
		const req: TokenRequest = { form: {}, headers: {} };
		await expect(callTokenEndpointAllowingDpopNonceError({ metadata }, req, c.dpop)).rejects.toThrow(ConditionFailed);
		expect(t.entries().at(-1)).toMatchObject({
			result: "FAILURE",
			msg: "The token endpoint returned a 'use_dpop_nonce' error but supplied no DPoP-Nonce header, leaving no nonce to retry the request with.",
		});
	});
});

describe("the resource server's use_dpop_nonce challenge (RFC9449-9)", () => {
	test("a 401 with the DPoP challenge keeps the nonce for the retry; a success rotates it", async () => {
		let calls = 0;
		server.use(
			http.get("https://rs.example/me", () => {
				calls++;
				if (calls === 1) {
					return new HttpResponse(null, {
						status: 401,
						headers: { "WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "rs-nonce-1" },
					});
				}
				return HttpResponse.json({ sub: "u" }, { headers: { "DPoP-Nonce": "rs-nonce-2" } });
			}),
		);
		const c = client();
		const accessToken = { value: "at", type: "DPoP" };
		const first = await callProtectedResourceAllowingDpopNonceError("https://rs.example/me", accessToken, c.dpop, {
			headers: { DPoP: "proof" },
		});
		expect(first.nonceError).toBe("rs-nonce-1");
		expect(c.dpop.resourceServerNonce).toBe("rs-nonce-1");
		const second = await callProtectedResourceAllowingDpopNonceError("https://rs.example/me", accessToken, c.dpop);
		expect(second.nonceError).toBeNull();
		expect(second.response.status).toBe(200);
		expect(c.dpop.resourceServerNonce).toBe("rs-nonce-2");
	});
});

const tokenResponse = (token_type: unknown): TokenResponse =>
	({ status: 200, endpoint_name: "token", headers: {}, body: null, json: { token_type } }) as TokenResponse;

describe("CheckTokenTypeIsDpop", () => {
	test("DPoP in any case; Bearer is not", () => {
		checkTokenTypeIsDpop(tokenResponse("dpop"));
		expect(t.entries().at(-1)).toMatchObject({
			src: "CheckTokenTypeIsDpop",
			result: "SUCCESS",
			msg: "Token type is DPoP",
		});
		expect(() => checkTokenTypeIsDpop(tokenResponse("Bearer"))).toThrow("CheckTokenTypeIsDpop: Token type is not DPoP");
		expect(() => checkTokenTypeIsDpop(tokenResponse(undefined))).toThrow("Couldn't find token type");
	});
});

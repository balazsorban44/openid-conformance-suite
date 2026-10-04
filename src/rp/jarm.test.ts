import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JSONWebKeySet } from "jose";
import { beforeAll, describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { generateJwkForAlg, type Jwks } from "../suite/jose.ts";
import { toPublicJWK } from "../suite/jose-jwk.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	addInvalidAudValueToJarm,
	addInvalidExpiredExpValueToJarm,
	addInvalidIssValueToJarm,
	addJARMToServerConfiguration,
	encryptJARMResponseIfConfigured,
	generateJARMResponseClaims,
	invalidateJarmSignature,
	removeAudFromJarm,
	removeExpFromJarm,
	removeIssFromJarm,
	sendJARMResponseWitResponseModeQuery,
	signJARMResponse,
	signJarmWithNullAlgorithm,
} from "./jarm.ts";

const t = useTestLog();
const lastEntry = () => t.entries().at(-1);

const ISSUER = "https://as.example/test/a/rp/";
/** The server's keys as FAPI2GenerateServerJWKs makes them: one PS256 signing key */
let keys: { jwks: Jwks; publicJwks: Jwks };
beforeAll(async () => {
	const key = { ...(await generateJwkForAlg("PS256")), kid: "server-1", use: "sig" };
	keys = { jwks: { keys: [key] }, publicJwks: { keys: [toPublicJWK(key)!] } };
});

const verify = (jarm: string) => jwtVerify(jarm, createLocalJWKSet(keys.publicJwks as JSONWebKeySet));

describe("AddJARMToServerConfiguration", () => {
	test("response_types code, response_modes jwt and the signing alg", () => {
		const server: Record<string, unknown> = {};
		addJARMToServerConfiguration(server, "PS256");
		expect(server).toEqual({
			response_types_supported: ["code"],
			response_modes_supported: ["jwt"],
			authorization_signing_alg_values_supported: ["PS256"],
		});
		expect(t.entries().map((e) => e.src)).toEqual([
			"AddResponseTypeCodeToServerConfiguration",
			"AddJARMResponseModeToServerConfiguration",
			"AddAuthorizationSigningAlgValuesSupportedToServerConfiguration",
		]);
	});
});

describe("GenerateJARMResponseClaims / SignJARMResponse", () => {
	test("iss, aud, code, state and an exp ten minutes ahead, signed with the server's key", async () => {
		const now = Math.floor(Date.now() / 1000);
		const claims = generateJARMResponseClaims(ISSUER, "c0de", "client-1", "st4te", "JARM-4.1.1");
		expect(claims).toMatchObject({ iss: ISSUER, aud: "client-1", code: "c0de", state: "st4te" });
		expect(claims["exp"] as number).toBeGreaterThanOrEqual(now + 600);
		expect(lastEntry()).toMatchObject({ src: "GenerateJARMResponseClaims", msg: "Created JARM response claims" });
		expect(generateJARMResponseClaims(ISSUER, "c0de", "client-1", null)).not.toHaveProperty("state");

		const jarm = await signJARMResponse(claims, keys.jwks, "JARM-4.1.1");
		expect(decodeProtectedHeader(jarm)).toMatchObject({ alg: "PS256", kid: expect.any(String) });
		const { payload } = await verify(jarm);
		expect(payload).toEqual(claims);
		expect(lastEntry()).toMatchObject({ src: "SignJARMResponse", msg: "Signed the JARM response", result: "SUCCESS" });
	});

	test("an encrypted response is only produced for a client that registered an encryption alg", async () => {
		const jarm = await signJARMResponse(generateJARMResponseClaims(ISSUER, "c", "client-1", null), keys.jwks);
		expect(encryptJARMResponseIfConfigured(jarm, { client_id: "client-1" })).toBe(jarm);
		expect(lastEntry()).toMatchObject({
			src: "EncryptJARMResponse",
			msg: "Skipped evaluation due to missing required element: client authorization_encrypted_response_alg",
			result: "INFO",
			requirements: ["JARM-3"],
		});
	});
});

describe("SendJARMResponseWitResponseModeQuery", () => {
	test("redirects to the redirect_uri with the response parameter", () => {
		const params = { redirect_uri: "https://rp.example/cb?x=1", code: "ignored" };
		const uri = sendJARMResponseWitResponseModeQuery(params, "a.b.c", "JARM-4.3.1");
		expect(uri).toBe("https://rp.example/cb?x=1&response=a.b.c");
		expect(params).toEqual({ code: "ignored" });
		expect(lastEntry()).toMatchObject({ msg: "Redirecting back to client", uri });
	});

	test("fails without a redirect_uri", () => {
		expect(() => sendJARMResponseWitResponseModeQuery({}, "a.b.c")).toThrow(TypeError);
	});
});

describe("the defects of the negative JARM modules", () => {
	const claims = () => generateJARMResponseClaims(ISSUER, "c0de", "client-1", "st4te");

	test("iss and aud are removed or made invalid, exp removed or expired", () => {
		let c = claims();
		removeIssFromJarm(c, "JARM-4.1.1");
		expect(c).not.toHaveProperty("iss");
		expect(lastEntry()).toMatchObject({ src: "RemoveIssFromJarm", msg: "Removed iss value from JARM claims" });
		c = claims();
		addInvalidIssValueToJarm(c);
		expect(c["iss"]).toBe(ISSUER + "1");
		c = claims();
		removeAudFromJarm(c);
		expect(c).not.toHaveProperty("aud");
		c = claims();
		addInvalidAudValueToJarm(c);
		expect(c["aud"]).toBe("client-11");
		c = claims();
		removeExpFromJarm(c);
		expect(c).not.toHaveProperty("exp");
		c = claims();
		addInvalidExpiredExpValueToJarm(c);
		expect(c["exp"] as number).toBeLessThan(Math.floor(Date.now() / 1000) - 300);
		expect(lastEntry()).toMatchObject({ msg: "Added expired exp value to JARM claims" });
		expect(() => addInvalidIssValueToJarm({})).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "jarm_response_claims does not contain iss", result: "FAILURE" });
	});

	test("the invalidated signature no longer verifies, the header and claims are unchanged", async () => {
		const jarm = await signJARMResponse(claims(), keys.jwks);
		const invalid = invalidateJarmSignature(jarm, "JARM-4.1.1");
		expect(invalid).not.toBe(jarm);
		expect(invalid.split(".").slice(0, 2)).toEqual(jarm.split(".").slice(0, 2));
		await expect(verify(invalid)).rejects.toThrow();
		expect(lastEntry()).toMatchObject({
			src: "InvalidateJarmSignature",
			msg: "Made the jarm_response signature invalid",
		});
	});

	test("the alg none response has no signature", () => {
		const jarm = signJarmWithNullAlgorithm(claims(), "JARM-4.1.1");
		const [header, payload, signature] = jarm.split(".");
		expect(JSON.parse(Buffer.from(header, "base64url").toString())).toEqual({ alg: "none" });
		expect(JSON.parse(Buffer.from(payload, "base64url").toString())).toMatchObject({ code: "c0de" });
		expect(signature).toBe("");
		expect(lastEntry()).toMatchObject({
			src: "SignJarmWithNullAlgorithm",
			msg: "Signed the JARM response with null algorithm",
		});
	});
});

import { createHash } from "node:crypto";
import { decodeProtectedHeader } from "jose";
import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	calculateAtHash,
	invalidateIdTokenSignature,
	oidccExtractServerSigningAlg,
	oidccSignIdToken,
	signIdTokenWithAlgNone,
} from "./id-token.ts";
import { oidccGenerateServerJWKs, oidccGenerateServerJWKsSingleSigningKeyWithNoKeyId } from "./jwks.ts";
import type { ServerKeys } from "./jwks.ts";
import type { RpClient } from "./registration.ts";

const t = useTestLog();
let generated: ServerKeys | null = null;
/** generated once (RSA key generation is slow), inside a test so the generation is logged somewhere */
const keysOf = (): ServerKeys => (generated ??= oidccGenerateServerJWKs());

describe("OIDCCExtractServerSigningAlg", () => {
	test("without id_token_signed_response_alg: the default algorithm of the first signing key (RSA: RS256)", () => {
		expect(oidccExtractServerSigningAlg({ client_id: "c" }, keysOf().jwks)).toBe("RS256");
		expect(t.entries().at(-1)).toMatchObject({
			msg: "Using the default algorithm for the first key in server jwks",
			signing_algorithm: "RS256",
		});
	});

	test("the client's alg when the OP has a key of that type", () => {
		expect(oidccExtractServerSigningAlg({ client_id: "c", id_token_signed_response_alg: "ES256" }, keysOf().jwks)).toBe(
			"ES256",
		);
		expect(oidccExtractServerSigningAlg({ client_id: "c", id_token_signed_response_alg: "HS256" }, keysOf().jwks)).toBe(
			"HS256",
		);
	});

	test("none is only allowed for clients that use the code response type only", () => {
		expect(oidccExtractServerSigningAlg({ client_id: "c", id_token_signed_response_alg: "none" }, keysOf().jwks)).toBe(
			"none",
		);
		const implicit: RpClient = { client_id: "c", id_token_signed_response_alg: "none", response_types: ["id_token"] };
		expect(() => oidccExtractServerSigningAlg(implicit, keysOf().jwks)).toThrow(ConditionFailed);
		expect(t.entries().at(-1)?.["msg"]).toBe(
			"none algorithm can only be used when only 'code' response type will be used",
		);
	});
});

describe("id_token signing", () => {
	test("OIDCCSignIdToken signs with the key for the client's alg and names it by kid", async () => {
		const jws = await oidccSignIdToken(
			{ iss: "https://op", sub: "s" },
			keysOf().jwks,
			{ client_id: "c" },
			"RS256",
			"OIDCC-2",
		);
		const kid = decodeProtectedHeader(jws).kid;
		const rsa = keysOf().jwks.keys.find((k) => k["kty"] === "RSA");
		expect(decodeProtectedHeader(jws).alg).toBe("RS256");
		expect(kid).toBe(rsa?.["kid"]);
		expect(t.entries().at(-1)).toMatchObject({
			src: "OIDCCSignIdToken",
			msg: "Signed the ID token",
			algorithm: "RS256",
		});
	});

	test("keys generated without kid sign without kid", async () => {
		const noKid = oidccGenerateServerJWKsSingleSigningKeyWithNoKeyId();
		const jws = await oidccSignIdToken({ sub: "s" }, noKid.jwks, { client_id: "c" }, "RS256");
		expect(decodeProtectedHeader(jws).kid).toBeUndefined();
		expect(noKid.publicJwks.keys.filter((k) => k["use"] === "sig").every((k) => k["kid"] == null)).toBe(true);
	});

	test("alg none: an unsecured JWS with an empty signature", () => {
		const jwt = signIdTokenWithAlgNone({ sub: "s" });
		const [header, payload, signature] = jwt.split(".");
		expect(JSON.parse(Buffer.from(header, "base64url").toString())).toEqual({ alg: "none" });
		expect(JSON.parse(Buffer.from(payload, "base64url").toString())).toEqual({ sub: "s" });
		expect(signature).toBe("");
	});

	test("InvalidateIdTokenSignature keeps header and payload and changes every signature byte", async () => {
		const jws = await oidccSignIdToken({ sub: "s" }, keysOf().jwks, { client_id: "c" }, "RS256");
		const invalid = invalidateIdTokenSignature(jws, "OIDCC-3.1.3.7");
		const [h, p, s] = jws.split(".");
		const [h2, p2, s2] = invalid.split(".");
		expect([h2, p2]).toEqual([h, p]);
		const a = Buffer.from(s, "base64url");
		const b = Buffer.from(s2, "base64url");
		expect(b.every((byte, i) => byte === (a[i] ^ 0x5a))).toBe(true);
	});
});

function half(alg: string, bytes: number): string {
	return createHash(alg).update("an-access-token").digest().subarray(0, bytes).toString("base64url");
}

test("at_hash: the left half of the digest the signing algorithm uses, base64url (OIDCC-3.3.2.11)", () => {
	expect(calculateAtHash("an-access-token", "RS256")).toBe(half("sha256", 16));
	expect(calculateAtHash("an-access-token", "ES384")).toBe(half("sha384", 24));
	expect(calculateAtHash("an-access-token", "EdDSA")).toBe(half("sha512", 32));
	expect(() => calculateAtHash("an-access-token", "XX1")).toThrow("CalculateAtHash: Unsupported algorithm");
});

import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { beforeAll, describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import type { IncomingRequest } from "../suite/server.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	createPAREndpointDpopErrorResponse,
	createResourceEndpointDpopErrorAltSchemeCaseResponse,
	createResourceEndpointDpopErrorResponse,
	createTokenEndpointDpopErrorResponse,
	ensureDpopProofJtiNotAlreadyUsed,
	extractDpopProofFromHeader,
	generateDpopAccessToken,
	performDpopProofResourceRequestChecks,
	performDpopProofTokenRequestChecks,
	validateDpopProofIat,
	validateDpopProofResourceRequest,
	validateDpopProofTokenRequest,
	validateTokenEndpointDpopProofNonce,
	type DpopProof,
} from "./dpop.ts";

type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

const t = useTestLog();
const lastEntry = () => t.entries().at(-1);

const TOKEN_ENDPOINT = "https://as.example/test/a/rp/token";

let privateKey: SigningKey;
let publicJwk: JWK;
let privateJwk: JWK;
let jkt: string;
beforeAll(async () => {
	const pair = await generateKeyPair("ES256", { extractable: true });
	privateKey = pair.privateKey;
	publicJwk = await exportJWK(pair.publicKey);
	privateJwk = await exportJWK(pair.privateKey);
	jkt = await calculateJwkThumbprint(publicJwk, "sha256");
});

let jtiCounter = 0;

/** A DPoP proof as openid-client sends one; `claims` and `header` override the defaults */
async function proof(
	claims: Record<string, unknown> = {},
	header: Record<string, unknown> = {},
	key: SigningKey = privateKey,
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({ jti: `jti-${++jtiCounter}`, htm: "POST", htu: TOKEN_ENDPOINT, iat: now, ...claims })
		.setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk, ...header })
		.sign(key);
}

function request(dpop: string | null, overrides: Partial<IncomingRequest> = {}): IncomingRequest {
	return {
		headers: dpop == null ? {} : { dpop },
		query_string_params: {},
		method: "POST",
		request_url: TOKEN_ENDPOINT,
		path: "token",
		...overrides,
	};
}

async function parsedProof(
	claims: Record<string, unknown> = {},
	header: Record<string, unknown> = {},
): Promise<DpopProof> {
	return extractDpopProofFromHeader(request(await proof(claims, header)));
}

describe("ExtractDpopProofFromHeader", () => {
	test("the DPoP header is parsed into value, header and claims", async () => {
		const jwt = await proof();
		const extracted = extractDpopProofFromHeader(request(jwt), "DPOP-4.3");
		expect(extracted.value).toBe(jwt);
		expect(extracted.header).toMatchObject({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk });
		expect(extracted.claims).toMatchObject({ htm: "POST", htu: TOKEN_ENDPOINT });
		expect(lastEntry()).toMatchObject({
			src: "ExtractDpopProofFromHeader",
			msg: "Found and parsed the incoming_dpop_proof from incoming_request",
			result: "SUCCESS",
			requirements: ["DPOP-4.3"],
		});
	});

	test("a request without the header fails", () => {
		expect(() => extractDpopProofFromHeader(request(null))).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "Couldn't find DPoP Proof header", result: "FAILURE" });
	});

	test("a header that is not a JWT fails", () => {
		expect(() => extractDpopProofFromHeader(request("not.a.jwt"))).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({
			msg: "Couldn't parse incoming_dpop_proof from incoming_request as a JWT",
			result: "FAILURE",
		});
	});
});

describe("ValidateDpopProofTokenRequest / ValidateDpopProofResourceRequest", () => {
	test("a valid token request proof passes and keeps the key's thumbprint", async () => {
		const p = await parsedProof();
		await validateDpopProofTokenRequest(p, request(p.value), "DPOP-4.3");
		expect(p.computed_dpop_jkt).toBe(jkt);
		expect(lastEntry()).toMatchObject({
			src: "ValidateDpopProofTokenRequest",
			msg: "DPoP Proof type, alg, jwk, jti, htm, htu, iat, exp, nbf passed validation checks",
			result: "SUCCESS",
		});
	});

	test("the query and fragment of htu are ignored", async () => {
		const p = await parsedProof({ htu: TOKEN_ENDPOINT + "?x=1#frag" });
		await validateDpopProofTokenRequest(p, request(p.value));
		expect(lastEntry()).toMatchObject({ result: "SUCCESS" });
	});

	test("htm must be the request's method, htu its url", async () => {
		const wrongMethod = await parsedProof({ htm: "GET" });
		await expect(validateDpopProofTokenRequest(wrongMethod, request(wrongMethod.value))).rejects.toThrow(
			ConditionFailed,
		);
		expect(lastEntry()).toMatchObject({
			msg: "Unexpected 'htm' in DPoP Proof",
			expected: "POST",
			actual: "GET",
			result: "FAILURE",
		});
		const wrongUrl = await parsedProof({ htu: "https://as.example/test/a/rp/par" });
		await expect(validateDpopProofTokenRequest(wrongUrl, request(wrongUrl.value))).rejects.toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "Unexpected 'htu' in DPoP Proof", expected: TOKEN_ENDPOINT });
	});

	test("typ must be dpop+jwt and alg a FAPI 2 one", async () => {
		const wrongTyp = await parsedProof({}, { typ: "JWT" });
		await expect(validateDpopProofTokenRequest(wrongTyp, request(wrongTyp.value))).rejects.toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "Invalid DPoP Proof 'typ' header", expected: "dpop+jwt", actual: "JWT" });
		const rsa = await generateKeyPair("RS256");
		const rsaProof = extractDpopProofFromHeader(
			request(await proof({}, { alg: "RS256", jwk: await exportJWK(rsa.publicKey) }, rsa.privateKey)),
		);
		await expect(validateDpopProofTokenRequest(rsaProof, request(rsaProof.value))).rejects.toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "Unsupported 'alg' claim in DPoP Proof header ", actual: "RS256" });
	});

	test("a private key in the jwk header fails (Nimbus refuses to parse the header)", async () => {
		const jwt = await proof({}, { jwk: privateJwk });
		expect(() => extractDpopProofFromHeader(request(jwt))).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({
			msg: "Couldn't parse incoming_dpop_proof from incoming_request as a JWT",
			result: "FAILURE",
		});
	});

	test("ath is refused on a token request and required on a resource request", async () => {
		const withAth = await parsedProof({ ath: "abc" });
		await expect(validateDpopProofTokenRequest(withAth, request(withAth.value))).rejects.toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "DPoP Proof request contains 'ath' claim" });
		const withoutAth = await parsedProof();
		await expect(validateDpopProofResourceRequest(withoutAth, request(withoutAth.value))).rejects.toThrow(
			ConditionFailed,
		);
		expect(lastEntry()).toMatchObject({ msg: "'ath' claim in DPoP Proof is missing" });
		await validateDpopProofResourceRequest(withAth, request(withAth.value));
		expect(lastEntry()).toMatchObject({ src: "ValidateDpopProofResourceRequest", result: "SUCCESS" });
	});

	test("an expired proof fails", async () => {
		const p = await parsedProof({ exp: Math.floor(Date.now() / 1000) - 600 });
		await expect(validateDpopProofTokenRequest(p, request(p.value))).rejects.toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "DPoP Proof has expired" });
	});
});

describe("ValidateDpopProofIat", () => {
	test("iat within five minutes passes, older fails", async () => {
		validateDpopProofIat(await parsedProof(), "DPOP-11.1");
		expect(lastEntry()).toMatchObject({ msg: "DPoP Proof iat value passed validation checks", result: "SUCCESS" });
		const old = await parsedProof({ iat: Math.floor(Date.now() / 1000) - 600 });
		expect(() => validateDpopProofIat(old)).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "DPoP Proof  'iat' is more than 5 minutes in the past" });
		const future = await parsedProof({ iat: Math.floor(Date.now() / 1000) + 600 });
		expect(() => validateDpopProofIat(future)).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "DPoP Proof 'iat' is in the future" });
	});
});

describe("EnsureDpopProofJtiNotAlreadyUsed", () => {
	test("a jti presented before fails", async () => {
		const cache: string[] = [];
		const p = await parsedProof({ jti: "same" });
		ensureDpopProofJtiNotAlreadyUsed(p, cache, "DPOP-4.2");
		expect(lastEntry()).toMatchObject({ msg: "Proof jti seems to be unique to this request", jti: "same" });
		expect(cache).toEqual(["same"]);
		expect(() => ensureDpopProofJtiNotAlreadyUsed(p, cache)).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({
			msg: "Proof jti is the same as one that was already presented to the conformance suite. jti must be unique in every DPoP Proof.",
			result: "FAILURE",
		});
	});
});

describe("Validate<Endpoint>DpopProofNonce", () => {
	test("no nonce required: none supplied is fine, one supplied is logged", async () => {
		expect(validateTokenEndpointDpopProofNonce(await parsedProof(), null)).toBeNull();
		expect(
			t
				.entries()
				.map((e) => e.msg)
				.slice(-2),
		).toEqual(["DPoP nonce not required", "Token endpoint DPoP nonce matches expected value"]);
		expect(validateTokenEndpointDpopProofNonce(await parsedProof({ nonce: "n" }), null)).toBeNull();
		expect(lastEntry()).toMatchObject({ msg: "DPoP Proof nonce supplied where none is expected" });
	});

	test("a required nonce that is missing or wrong is returned for the error response", async () => {
		expect(validateTokenEndpointDpopProofNonce(await parsedProof(), "n1")).toBe("n1");
		expect(
			t
				.entries()
				.map((e) => e.msg)
				.slice(-2),
		).toEqual(["DPoP Proof nonce not supplied", "Token endpoint DPoP nonce is invalid"]);
		expect(validateTokenEndpointDpopProofNonce(await parsedProof({ nonce: "n0" }), "n1")).toBe("n1");
		expect(t.entries().at(-2)).toMatchObject({ msg: "DPoP Proof nonce is invalid", expected: "n1", actual: "n0" });
		expect(validateTokenEndpointDpopProofNonce(await parsedProof({ nonce: "n1" }), "n1")).toBeNull();
		expect(lastEntry()).toMatchObject({ msg: "Token endpoint DPoP nonce matches expected value", result: "SUCCESS" });
	});
});

describe("PerformDpopProof<Endpoint>RequestChecks", () => {
	test("the token request sequence passes a proof bound to the authorization code's key", async () => {
		const p = await parsedProof({ nonce: "n1" });
		const nonceError = await performDpopProofTokenRequestChecks(
			p,
			request(p.value),
			{ authorizationServer: "n1", resourceServer: null },
			[],
			jkt,
		);
		expect(nonceError).toBeNull();
		expect(t.entries().map((e) => e.src)).toEqual([
			"ExtractDpopProofFromHeader",
			"ValidateDpopProofTokenRequest",
			"ValidateDpopProofIat",
			"ValidateDpopProofNbf",
			"EnsureDpopProofJtiNotAlreadyUsed",
			"ValidateTokenEndpointDpopProofNonce",
			"ValidateDpopProofSignature",
			"ValidateAuthorizationCodeDpopBindingKey",
		]);
		expect(t.entries().filter((e) => e.result === "FAILURE" || e.result === "WARNING")).toEqual([]);
	});

	test("a missing nonce is a warning and the expected nonce is returned; a bad signature fails", async () => {
		const other = await generateKeyPair("ES256");
		const p = extractDpopProofFromHeader(request(await proof({}, {}, other.privateKey)));
		const nonceError = await performDpopProofTokenRequestChecks(
			p,
			request(p.value),
			{ authorizationServer: "n2", resourceServer: null },
			[],
			jkt,
		);
		expect(nonceError).toBe("n2");
		// the nonce check never fails: the endpoint answers the use_dpop_nonce error instead
		expect(t.entries().filter((e) => e.src === "ValidateTokenEndpointDpopProofNonce")).toMatchObject([
			{ msg: "DPoP Proof nonce not supplied", expected: "n2" },
			{ msg: "Token endpoint DPoP nonce is invalid", expected: "n2" },
		]);
		expect(
			t
				.entries()
				.filter((e) => e.result === "FAILURE")
				.map((e) => e.src),
		).toEqual(["ValidateDpopProofSignature"]);
	});

	test("the resource request sequence checks the resource server's nonce", async () => {
		const p = await parsedProof({ ath: "x", nonce: "rs1" });
		const nonceError = await performDpopProofResourceRequestChecks(
			p,
			request(p.value),
			{ authorizationServer: "as1", resourceServer: "rs1" },
			[],
		);
		expect(nonceError).toBeNull();
		expect(t.entries().filter((e) => e.result === "FAILURE" || e.result === "WARNING")).toEqual([]);
	});
});

describe("GenerateDpopAccessToken", () => {
	test("a random token bound to the proof's key", async () => {
		const token = await generateDpopAccessToken(await parsedProof());
		expect(token.jkt).toBe(jkt);
		expect(token.value).toMatch(/^[A-Za-z0-9]{50}$/);
		expect(lastEntry()).toMatchObject({
			src: "GenerateDpopAccessToken",
			msg: "Generated DPoP access token and jkt for DPoP Proof JWK",
			result: "SUCCESS",
		});
	});
});

describe("Create<Endpoint>DpopErrorResponse", () => {
	test("the authorization server endpoints answer 400 use_dpop_nonce with the nonce to use", () => {
		expect(createTokenEndpointDpopErrorResponse("n1")).toEqual({
			status: 400,
			headers: { "DPoP-Nonce": "n1" },
			body: { error: "use_dpop_nonce", error_description: "Authorization server requires nonce in DPoP proof" },
		});
		expect(lastEntry()).toMatchObject({
			src: "CreateTokenEndpointDpopErrorResponse",
			msg: "Condition ran but did not log anything",
		});
		expect(createPAREndpointDpopErrorResponse("n2").headers).toEqual({ "DPoP-Nonce": "n2" });
		expect(lastEntry()).toMatchObject({ src: "CreatePAREndpointDpopErrorResponse" });
	});

	test("the resource server answers 401 with a WWW-Authenticate challenge, in the DPoP or dPoP scheme", () => {
		expect(createResourceEndpointDpopErrorResponse("r1")).toEqual({
			status: 401,
			headers: {
				"WWW-Authenticate":
					'DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"',
				"DPoP-Nonce": "r1",
			},
			body: null,
		});
		expect(createResourceEndpointDpopErrorAltSchemeCaseResponse("r2").headers["WWW-Authenticate"]).toMatch(
			/^dPoP error="use_dpop_nonce"/,
		);
		expect(lastEntry()).toMatchObject({ src: "CreateResourceEndpointDpopErrorAltSchemeCaseResponse" });
	});
});

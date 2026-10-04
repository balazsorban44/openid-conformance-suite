import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { beforeAll, describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import type { IncomingRequest } from "../suite/server.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	checkForClientAssertionJtiReuse,
	ensureClientAssertionSignatureAlgorithmMatchesRegistered,
	ensureClientAssertionTypeIsJwt,
	extractClientAssertion,
	validateClientAssertionAudClaimIsIssuerAsString,
	validateClientAssertionClaims,
	validateClientAssertionSignature,
	validateClientAuthenticationWithPrivateKeyJWT,
	type ClientAssertion,
} from "./client-assertion.ts";
import type { RpClient } from "./registration.ts";

type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

const t = useTestLog();
const lastEntry = () => t.entries().at(-1);

const ISSUER = "https://as.example/test/a/rp/";
const server = {
	issuer: ISSUER,
	token_endpoint: ISSUER + "token",
	pushed_authorization_request_endpoint: ISSUER + "par",
	mtls_endpoint_aliases: { token_endpoint: "https://as.example/test-mtls/a/rp/token" },
};
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

let privateKey: SigningKey;
let publicJwk: JWK;
let client: RpClient;
beforeAll(async () => {
	const pair = await generateKeyPair("PS256");
	privateKey = pair.privateKey;
	publicJwk = { ...(await exportJWK(pair.publicKey)), kid: "rp-key-1", alg: "PS256", use: "sig" };
	client = { client_id: "client-1", jwks: { keys: [publicJwk] } };
});

let jtiCounter = 0;

/** A client assertion as openid-client's PrivateKeyJwt sends one */
async function assertion(
	claims: Record<string, unknown> = {},
	header: Record<string, unknown> = {},
	key: SigningKey = privateKey,
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({
		iss: "client-1",
		sub: "client-1",
		aud: ISSUER,
		jti: `jti-${++jtiCounter}`,
		iat: now,
		exp: now + 60,
		...claims,
	})
		.setProtectedHeader({ alg: "PS256", kid: "rp-key-1", ...header })
		.sign(key);
}

function request(form: Record<string, string>): IncomingRequest {
	return {
		headers: {},
		query_string_params: {},
		method: "POST",
		request_url: ISSUER + "token",
		path: "token",
		body_form_params: form,
	};
}

async function parsed(
	claims: Record<string, unknown> = {},
	header: Record<string, unknown> = {},
	key: SigningKey = privateKey,
): Promise<ClientAssertion> {
	return extractClientAssertion(request({ client_assertion: await assertion(claims, header, key) }));
}

describe("ExtractClientAssertion", () => {
	test("the client_assertion form parameter is parsed", async () => {
		const jwt = await assertion();
		const a = extractClientAssertion(request({ client_assertion: jwt }), "RFC7523-2.2");
		expect(a.value).toBe(jwt);
		expect(a.header).toMatchObject({ alg: "PS256", kid: "rp-key-1" });
		expect(a.claims).toMatchObject({ iss: "client-1", aud: ISSUER });
		expect(lastEntry()).toMatchObject({
			msg: "Parsed client assertion",
			result: "SUCCESS",
			requirements: ["RFC7523-2.2"],
		});
	});

	test("a request without one fails", () => {
		expect(() => extractClientAssertion(request({}))).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({
			msg: "Could not find client assertion in request parameters",
			result: "FAILURE",
		});
		expect(() => extractClientAssertion(request({ client_assertion: "nope" }))).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "Couldn't parse client assertion", result: "FAILURE" });
	});
});

describe("EnsureClientAssertionSignatureAlgorithmMatchesRegistered", () => {
	test("any algorithm without a registered one, the registered one otherwise", async () => {
		const a = await parsed();
		ensureClientAssertionSignatureAlgorithmMatchesRegistered(a, client, "OIDCR-2");
		expect(lastEntry()).toMatchObject({
			msg: "token_endpoint_auth_signing_alg is not set for the client, any supported algorithm can be used",
		});
		ensureClientAssertionSignatureAlgorithmMatchesRegistered(a, {
			...client,
			token_endpoint_auth_signing_alg: "PS256",
		});
		expect(lastEntry()).toMatchObject({
			msg: "Client assertion is signed using the registered token_endpoint_auth_signing_alg algorithm",
			result: "SUCCESS",
		});
		expect(() =>
			ensureClientAssertionSignatureAlgorithmMatchesRegistered(a, {
				...client,
				token_endpoint_auth_signing_alg: "ES256",
			}),
		).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ expected: "ES256", actual: "PS256", result: "FAILURE" });
	});
});

describe("ValidateClientAssertionSignature", () => {
	test("verifies with the client's configured key, by kid", async () => {
		await validateClientAssertionSignature(await parsed(), client, "OIDCC-9");
		expect(lastEntry()).toMatchObject({ src: "ValidateClientAssertionSignature", result: "SUCCESS" });
	});

	test("another key or a missing kid fails", async () => {
		const other = await generateKeyPair("PS256");
		await expect(validateClientAssertionSignature(await parsed({}, {}, other.privateKey), client)).rejects.toThrow(
			ConditionFailed,
		);
		expect(lastEntry()).toMatchObject({ src: "ValidateClientAssertionSignature", result: "FAILURE" });
		await expect(validateClientAssertionSignature(await parsed({}, { kid: undefined }), client)).rejects.toThrow(
			ConditionFailed,
		);
		expect(lastEntry()).toMatchObject({ result: "FAILURE" });
	});
});

describe("EnsureClientAssertionTypeIsJwt", () => {
	test("the jwt-bearer type is required", () => {
		ensureClientAssertionTypeIsJwt(request({ client_assertion_type: JWT_BEARER }), "RFC7523-2.2");
		expect(lastEntry()).toMatchObject({ msg: "Found JWT assertion type", result: "SUCCESS" });
		expect(() => ensureClientAssertionTypeIsJwt(request({}))).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "client_assertion_type missing from request parameters" });
		expect(() => ensureClientAssertionTypeIsJwt(request({ client_assertion_type: "saml" }))).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "client_assertion_type does not match JWT", actual: "saml" });
	});
});

describe("ValidateClientAssertionClaims", () => {
	test("iss and sub are the client_id, aud this server, with jti, iat and exp", async () => {
		validateClientAssertionClaims(await parsed(), client, server, {}, "RFC7523-3", "OIDCC-9");
		expect(lastEntry()).toMatchObject({
			src: "ValidateClientAssertionClaims",
			msg: "Client Assertion passed all validation checks",
			result: "SUCCESS",
			requirements: ["RFC7523-3", "OIDCC-9"],
		});
	});

	test("the token endpoint accepts the issuer, the token endpoint and its mTLS alias as aud", async () => {
		for (const aud of [ISSUER + "token", "https://as.example/test-mtls/a/rp/token", [ISSUER, "other"]]) {
			validateClientAssertionClaims(await parsed({ aud }), client, server);
			expect(lastEntry()).toMatchObject({ result: "SUCCESS" });
		}
		expect(() => validateClientAssertionClaims({} as never, client, server)).toThrow();
		expect(() => validateClientAssertionClaims(parsedSync({ aud: ISSUER + "par" }), client, server)).toThrow(
			ConditionFailed,
		);
		expect(lastEntry()).toMatchObject({
			msg: "aud mismatch",
			expected: [ISSUER + "token", "https://as.example/test-mtls/a/rp/token"],
		});
	});

	test("the PAR endpoint also accepts its own url as aud", async () => {
		validateClientAssertionClaims(
			await parsed({ aud: ISSUER + "par" }),
			client,
			server,
			{ forParEndpoint: true },
			"PAR-2",
		);
		expect(lastEntry()).toMatchObject({
			src: "ValidateClientAssertionClaimsForPAREndpoint",
			msg: "Client Assertion passed all validation checks",
			requirements: ["PAR-2"],
		});
		expect(() =>
			validateClientAssertionClaims(parsedSync({ aud: "https://other.example" }), client, server, {
				forParEndpoint: true,
			}),
		).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "aud claim is not one of the expected values" });
	});

	test("a wrong issuer or subject, a missing jti and a bad lifetime fail", async () => {
		const now = Math.floor(Date.now() / 1000);
		const cases: [Record<string, unknown>, string][] = [
			[{ iss: "someone-else" }, "Issuer mismatch"],
			[{ sub: "someone-else" }, "Subject mismatch"],
			[{ jti: undefined }, "Missing JWT ID"],
			[{ exp: undefined }, "Missing exp"],
			[{ exp: now - 600 }, "Assertion expired"],
			[{ exp: now + 2 * 24 * 3600 }, "Assertion expires unreasonable far in the future"],
			[{ nbf: now + 600 }, "Assertion 'nbf' value is in the future'"],
			[{ iat: undefined }, "Missing iat"],
		];
		for (const [claims, msg] of cases) {
			const a = await parsed(claims);
			expect(() => validateClientAssertionClaims(a, client, server)).toThrow(ConditionFailed);
			expect(lastEntry()).toMatchObject({ msg, result: "FAILURE" });
		}
	});
});

describe("CheckForClientAssertionJtiReuse", () => {
	test("a jti presented before fails", async () => {
		const used = new Set<string>();
		const a = await parsed({ jti: "once" });
		checkForClientAssertionJtiReuse(a, used, "RFC7523-3");
		expect(lastEntry()).toMatchObject({ result: "SUCCESS" });
		expect(used.has("once")).toBe(true);
		expect(() => checkForClientAssertionJtiReuse(a, used)).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ result: "FAILURE" });
		expect(() => checkForClientAssertionJtiReuse(parsedSync({ jti: undefined }), used)).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({ msg: "jti claim missing on client_assertion" });
	});
});

describe("ValidateClientAssertionAudClaimIsIssuerAsString", () => {
	test("FAPI 2: the aud is the issuer, as a string", async () => {
		validateClientAssertionAudClaimIsIssuerAsString(await parsed(), ISSUER, "FAPI2-SP-ID2-5.3.2.1-9");
		expect(lastEntry()).toMatchObject({
			msg: "private_key_jwt client Assertion 'aud' claim matches the authentication server issuer url",
			result: "SUCCESS",
		});
		expect(() => validateClientAssertionAudClaimIsIssuerAsString(parsedSync({ aud: [ISSUER] }), ISSUER)).toThrow(
			ConditionFailed,
		);
		expect(lastEntry()).toMatchObject({ msg: "private_key_jwt aud claim is an array but should be a simple string" });
		expect(() =>
			validateClientAssertionAudClaimIsIssuerAsString(parsedSync({ aud: ISSUER + "token" }), ISSUER),
		).toThrow(ConditionFailed);
		expect(lastEntry()).toMatchObject({
			msg: "private_key_jwt aud claim does not match the authentication server issuer url",
		});
		expect(() => validateClientAssertionAudClaimIsIssuerAsString(parsedSync({ aud: undefined }), ISSUER)).toThrow(
			ConditionFailed,
		);
		expect(lastEntry()).toMatchObject({ msg: "Missing aud not present in private_key_jwt client assertion" });
	});
});

describe("ValidateClientAuthenticationWithPrivateKeyJWT", () => {
	test("the sequence of a token request", async () => {
		const used = new Set<string>();
		const req = request({ client_assertion: await assertion(), client_assertion_type: JWT_BEARER });
		const a = await validateClientAuthenticationWithPrivateKeyJWT(req, client, server, used);
		expect(a.claims["iss"]).toBe("client-1");
		expect(t.entries().map((e) => e.src)).toEqual([
			"ExtractClientAssertion",
			"EnsureClientAssertionSignatureAlgorithmMatchesRegistered",
			"ValidateClientAssertionSignature",
			"EnsureClientAssertionTypeIsJwt",
			"ValidateClientAssertionClaims",
			"CheckForClientAssertionJtiReuse",
		]);
		expect(t.entries().filter((e) => e.result === "FAILURE")).toEqual([]);
	});

	test("the PAR endpoint's variant; a failing check is recorded and the next one still runs", async () => {
		const other = await generateKeyPair("PS256");
		const req = request({ client_assertion: await assertion({ aud: ISSUER + "par" }, {}, other.privateKey) });
		await validateClientAuthenticationWithPrivateKeyJWT(req, client, server, new Set(), { forParEndpoint: true });
		expect(t.entries().map((e) => e.src)).toContain("ValidateClientAssertionClaimsForPAREndpoint");
		expect(
			t
				.entries()
				.filter((e) => e.result === "FAILURE")
				.map((e) => e.src),
		).toEqual(["ValidateClientAssertionSignature", "EnsureClientAssertionTypeIsJwt"]);
		expect(lastEntry()).toMatchObject({ src: "CheckForClientAssertionJtiReuse", result: "SUCCESS" });
	});

	test("a request without an assertion stops the test (UPSTREAM: continues with failures)", async () => {
		await expect(validateClientAuthenticationWithPrivateKeyJWT(request({}), client, server, new Set())).rejects.toThrow(
			ConditionFailed,
		);
	});
});

/** An assertion built from claims only (no signature check involved): the parsed form the claim checks read */
function parsedSync(claims: Record<string, unknown>): ClientAssertion {
	const now = Math.floor(Date.now() / 1000);
	const all: Record<string, unknown> = {
		iss: "client-1",
		sub: "client-1",
		aud: ISSUER,
		jti: "j",
		iat: now,
		exp: now + 60,
		...claims,
	};
	for (const k of Object.keys(all)) {
		if (all[k] === undefined) {
			delete all[k];
		}
	}
	return { value: "h.p.s", header: { alg: "PS256", kid: "rp-key-1" }, claims: all };
}

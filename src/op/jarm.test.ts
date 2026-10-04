import { importJWK, SignJWT } from "jose";
import { beforeAll, describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { generateJwkForAlg, publicJwks, type JWK, type Jwks, type ParsedJwt } from "../suite/jose.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	extractAuthorizationEndpointResponseFromJARMResponse,
	extractJARMFromURLQuery,
	fapi2ValidateJarmSigningAlg,
	rejectNonJarmResponsesInUrlQuery,
	validateJARMExpRecommendations,
	validateJARMResponse,
	validateJARMSignatureUsingKid,
} from "./jarm.ts";

const t = useTestLog();

const op = { metadata: { issuer: "https://op.example" } };
const client = { client: { client_id: "c1" }, keys: null };
let serverKey: JWK;
let serverJwks: Jwks;
beforeAll(async () => {
	serverKey = await generateJwkForAlg("ES256");
	serverJwks = publicJwks({ keys: [serverKey] });
});

/** A JARM response as an OP signs it: the authorization response as claims of a JWT with iss, aud and exp */
async function jarmResponse(claims: Record<string, unknown>, key = serverKey, alg = "ES256"): Promise<string> {
	return new SignJWT(claims)
		.setProtectedHeader({ alg, kid: String(key["kid"]) })
		.sign(await importJWK(key as never, alg));
}

const now = Math.floor(Date.now() / 1000);
const good = { iss: "https://op.example", aud: "c1", exp: now + 300, iat: now, code: "the-code", state: "s" };

describe("the JARM response of the redirect_uri query (JARM-2.1)", () => {
	test("is parsed, is the only parameter, and its claims minus the JWT ones are the authorization response", async () => {
		const jwt = await jarmResponse(good);
		const jarm = await extractJARMFromURLQuery({ query: { response: jwt } }, client, "JARM-2.3.1");
		expect(jarm.claims).toEqual(good);
		expect(jarm.header).toMatchObject({ alg: "ES256", kid: serverKey["kid"] });

		rejectNonJarmResponsesInUrlQuery({ query: { response: jwt } }, "https://suite.example/cb", "JARM-2.1");
		// the query the second client's redirect_uri is registered with is not an extra parameter
		rejectNonJarmResponsesInUrlQuery(
			{ query: { response: jwt, dummy1: "lorem", dummy2: "ipsum" } },
			"https://suite.example/cb?dummy1=lorem&dummy2=ipsum",
		);
		expect(() =>
			rejectNonJarmResponsesInUrlQuery({ query: { response: jwt, code: "x" } }, "https://suite.example/cb"),
		).toThrow("When using JARM, The authorization endpoint response should only contain 'response' containing a JWT.");

		expect(extractAuthorizationEndpointResponseFromJARMResponse(jarm)).toEqual({
			iss: "https://op.example",
			code: "the-code",
			state: "s",
		});
		expect(t.entries().map((e) => [e.src, e["result"]])).toEqual([
			["ExtractJARMFromURLQuery", "SUCCESS"],
			["RejectNonJarmResponsesInUrlQuery", "SUCCESS"],
			["RejectNonJarmResponsesInUrlQuery", "SUCCESS"],
			["RejectNonJarmResponsesInUrlQuery", "FAILURE"],
			["ExtractAuthorizationEndpointResponseFromJARMResponse", "SUCCESS"],
		]);
	});

	test("a response that is not a JWT fails ExtractJARMFromURLQuery", async () => {
		await expect(extractJARMFromURLQuery({ query: { response: "not-a-jwt" } }, client)).rejects.toThrow(
			ConditionFailed,
		);
		expect(t.entries().at(-1)).toMatchObject({
			src: "ExtractJARMFromURLQuery",
			result: "FAILURE",
			msg: "Couldn't parse jarm_response from callback_query_params as a JWT",
		});
	});
});

/** A parsed JARM response with these claims (the signature is not checked by the claim checks) */
const parsed = (claims: Record<string, unknown>, alg = "ES256"): ParsedJwt => ({
	value: "",
	header: { alg },
	claims,
});

describe("the JARM claims (JARM-2.4)", () => {
	test("iss, aud (a string or an array) and exp are checked against the OP and the client", () => {
		validateJARMResponse(op, client.client, parsed(good), "JARM-2.4-2");
		validateJARMResponse(op, client.client, parsed({ ...good, aud: ["other", "c1"] }));
		expect(t.entries().map((e) => [e.src, e["result"], e["msg"]])).toEqual([
			["ValidateJARMResponse", "SUCCESS", "JARM response standard JWT claims are valid"],
			["ValidateJARMResponse", "SUCCESS", "JARM response standard JWT claims are valid"],
		]);
		expect(() => validateJARMResponse(op, client.client, parsed({ ...good, iss: "https://other" }))).toThrow(
			"Issuer mismatch",
		);
		expect(() => validateJARMResponse(op, client.client, parsed({ ...good, aud: "c2" }))).toThrow("Audience mismatch");
		expect(() => validateJARMResponse(op, client.client, parsed({ ...good, exp: now - 600 }))).toThrow("Token expired");
		expect(() => validateJARMResponse(op, client.client, parsed({ ...good, exp: undefined }))).toThrow(
			"Missing expiration",
		);
		expect(() => validateJARMResponse(op, client.client, parsed({ ...good, iat: now + 600 }))).toThrow(
			"Token issued in the future",
		);
	});

	test("exp should be within 10 minutes and at least 10 seconds away", () => {
		validateJARMExpRecommendations(parsed(good), "JARM-2.1");
		expect(t.entries().at(-1)).toMatchObject({ result: "SUCCESS", msg: "JARM response 'exp' is less than 10 minutes" });
		expect(() => validateJARMExpRecommendations(parsed({ ...good, exp: now + 20 * 60 }))).toThrow(
			"JARM 'exp' time is further in the future than the recommended 10 minutes",
		);
		expect(() => validateJARMExpRecommendations(parsed({ ...good, exp: now + 5 }))).toThrow(
			"JARM 'exp' time appears to be less than 10 seconds",
		);
	});

	test("FAPI 2.0 permits PS256, ES256 and EdDSA signatures (FAPI2-SP-FINAL-5.4)", () => {
		fapi2ValidateJarmSigningAlg(parsed(good, "PS256"));
		expect(t.entries().at(-1)).toMatchObject({
			src: "FAPI2ValidateJarmSigningAlg",
			result: "SUCCESS",
			alg: "PS256",
			permitted: ["PS256", "ES256", "EdDSA", "Ed25519"],
		});
		expect(() => fapi2ValidateJarmSigningAlg(parsed(good, "RS256"))).toThrow(
			"JARM response must be signed with a permitted alg",
		);
	});
});

describe("the JARM signature (JARM-2.4-5)", () => {
	test("verifies with the OP's key of the header's kid, and not with another key", async () => {
		const jwt = await jarmResponse(good);
		const jarm = await extractJARMFromURLQuery({ query: { response: jwt } }, client);
		await validateJARMSignatureUsingKid(jarm, serverJwks, "JARM-2.4-5");
		expect(t.entries().at(-1)).toMatchObject({
			src: "ValidateJARMSignatureUsingKid",
			result: "SUCCESS",
			msg: "jarm_response signature validated",
		});

		const otherKey = await generateJwkForAlg("ES256");
		const otherJwks = publicJwks({ keys: [{ ...otherKey, kid: serverKey["kid"] }] });
		await expect(validateJARMSignatureUsingKid(jarm, otherJwks)).rejects.toThrow(ConditionFailed);
	});
});

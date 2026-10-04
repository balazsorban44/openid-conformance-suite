import { http, HttpResponse } from "msw";
import { beforeAll, describe, expect, test } from "vitest";
import { generateJwkForAlg, publicJwks } from "../suite/jose.ts";
import { useMswServer, useTestLog } from "../suite/testing.ts";
import type { ClientKeys } from "./registration.ts";
import {
	addArrayContainingIssuerAndAnotherValueAsAudToClientAuthenticationAssertionClaims,
	addPAREndpointAsAudToClientAuthenticationAssertionClaims,
	callTokenEndpointAllowingTLSFailure,
	changeClientJwksAlgToRS256,
	createJWTClientAuthenticationAssertionWithIssAudAndAddToRequest,
	createUnsecuredClientAuthenticationAssertion,
	invalidateClientAssertionSignature,
	removeClientAssertionFromRequest,
	removeClientAssertionTypeFromRequest,
	removeSubFromClientAssertionClaims,
	setClientAssertionTypeToWrongValue,
	type TokenRequest,
} from "./token.ts";

const t = useTestLog();
const server = useMswServer();

const op = {
	metadata: {
		issuer: "https://op.example",
		token_endpoint: "https://op.example/token",
		pushed_authorization_request_endpoint: "https://op.example/par",
	},
};
let keys: ClientKeys;
beforeAll(async () => {
	const key = await generateJwkForAlg("PS256");
	keys = { jwks: { keys: [key] }, publicJwks: publicJwks({ keys: [key] }) };
});
const client = () => ({ client: { client_id: "c1" }, keys: structuredClone(keys) });

function decode(jwt: string): { header: Record<string, unknown>; claims: Record<string, unknown>; signature: string } {
	const [h, p, s] = jwt.split(".");
	return {
		header: JSON.parse(Buffer.from(h, "base64url").toString()),
		claims: JSON.parse(Buffer.from(p, "base64url").toString()),
		signature: s,
	};
}

describe("private_key_jwt with the issuer as audience (FAPI2-SP-FINAL-5.3.2.1-8)", () => {
	test("iss and sub are the client_id, aud the issuer, 60 seconds of validity, signed with the client's key", async () => {
		const req: TokenRequest = { form: { grant_type: "authorization_code" }, headers: {} };
		await createJWTClientAuthenticationAssertionWithIssAudAndAddToRequest(op, req, client());
		expect(req.form["client_assertion_type"]).toBe("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		const { header, claims } = decode(req.form["client_assertion"] as string);
		expect(header).toMatchObject({ alg: "PS256", kid: keys.jwks.keys[0]["kid"] });
		expect(claims).toMatchObject({ iss: "c1", sub: "c1", aud: "https://op.example" });
		expect(claims["exp"]).toBe((claims["iat"] as number) + 60);
		expect(claims["nbf"]).toBe(claims["iat"]);
		expect(typeof claims["jti"]).toBe("string");
		expect(t.entries().map((e) => [e.src, e["result"]])).toEqual([
			["CreateClientAuthenticationAssertionClaimsWithIssAudience", "SUCCESS"],
			["SignClientAuthenticationAssertion", "SUCCESS"],
			["AddClientAssertionToRequest", undefined],
		]);

		removeClientAssertionFromRequest(req);
		expect(req.form).toEqual({ grant_type: "authorization_code" });
	});

	test("the invalid assertions of the negative modules", async () => {
		const assertion = async (
			mutation: Parameters<typeof createJWTClientAuthenticationAssertionWithIssAudAndAddToRequest>[3],
		) => {
			const req: TokenRequest = { form: {}, headers: {} };
			await createJWTClientAuthenticationAssertionWithIssAudAndAddToRequest(op, req, client(), mutation);
			return req.form;
		};
		expect(
			await assertion({ afterAdd: (req) => removeClientAssertionTypeFromRequest(req, "RFC7521-4.2") }),
		).not.toHaveProperty("client_assertion_type");
		expect(
			(await assertion({ afterAdd: (req) => setClientAssertionTypeToWrongValue(req, "RFC7521-4.2") }))[
				"client_assertion_type"
			],
		).not.toBe("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		const noSub = await assertion({ afterClaims: (claims) => removeSubFromClientAssertionClaims(claims, "RFC7523-3") });
		expect(decode(noSub["client_assertion"] as string).claims).not.toHaveProperty("sub");

		const parAud = await assertion({
			afterClaims: (claims) =>
				addPAREndpointAsAudToClientAuthenticationAssertionClaims(claims, op, "FAPI2-SP-FINAL-5.3.2.1-8"),
		});
		expect(decode(parAud["client_assertion"] as string).claims["aud"]).toBe("https://op.example/par");
		const arrayAud = await assertion({
			afterClaims: (claims) =>
				addArrayContainingIssuerAndAnotherValueAsAudToClientAuthenticationAssertionClaims(
					claims,
					op,
					"FAPI2-SP-FINAL-5.3.2.1-8",
				),
		});
		expect(decode(arrayAud["client_assertion"] as string).claims["aud"]).toEqual(
			expect.arrayContaining(["https://op.example"]),
		);

		const c = client();
		const rs256: TokenRequest = { form: {}, headers: {} };
		await createJWTClientAuthenticationAssertionWithIssAudAndAddToRequest(op, rs256, c, {
			beforeSign: () => changeClientJwksAlgToRS256(c, "FAPI2-SP-FINAL-5.4"),
		});
		expect(decode(rs256.form["client_assertion"] as string).header["alg"]).toBe("RS256");

		const none = await assertion({
			sign: async (claims) => createUnsecuredClientAuthenticationAssertion(claims, "RFC7523-3", "FAPI2-SP-FINAL-5.4"),
		});
		const unsecured = decode(none["client_assertion"] as string);
		expect(unsecured.header).toEqual({ alg: "none" });
		expect(unsecured.signature).toBe("");
		expect(unsecured.claims).toMatchObject({ iss: "c1", aud: "https://op.example" });

		const valid = await assertion({});
		const invalid = await assertion({ afterSign: (jws) => invalidateClientAssertionSignature(jws, "RFC7523-3") });
		expect(decode(invalid["client_assertion"] as string).signature).not.toBe(
			decode(valid["client_assertion"] as string).signature,
		);
		expect(decode(invalid["client_assertion"] as string).claims["aud"]).toBe("https://op.example");
	});
});

describe("CallTokenEndpointAllowingTLSFailure", () => {
	test("a dropped connection is an accepted answer (the OP may refuse at the TLS layer)", async () => {
		server.use(http.post("https://op.example/token", () => HttpResponse.error()));
		const { response, sslError } = await callTokenEndpointAllowingTLSFailure(
			op,
			{ form: { grant_type: "authorization_code" }, headers: {} },
			"FAPI2-SP-FINAL-5.3.2.1-6",
		);
		expect(sslError).toBe(true);
		expect(response).toBeNull();
		expect(t.entries().at(-1)).toMatchObject({
			src: "CallTokenEndpointAllowingTLSFailure",
			result: "SUCCESS",
			msg: "Call to token_endpoint failed due to a TLS issue",
			requirements: ["FAPI2-SP-FINAL-5.3.2.1-6"],
		});
	});

	test("an HTTP error response is a response", async () => {
		server.use(
			http.post("https://op.example/token", () => HttpResponse.json({ error: "invalid_request" }, { status: 400 })),
		);
		const { response, sslError } = await callTokenEndpointAllowingTLSFailure(op, { form: {}, headers: {} });
		expect(sslError).toBe(false);
		expect(response).toMatchObject({ status: 400, json: { error: "invalid_request" } });
	});
});

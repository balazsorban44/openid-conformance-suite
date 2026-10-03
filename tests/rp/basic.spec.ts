/**
 * OpenID Connect Core: Basic Certification Profile, RP tests (upstream openid/client/OIDCCClientBasicTestPlan.java,
 * the tests of the profile document's table, in its order).
 *
 * The plan fixes response_type=code, response_mode=default and client_auth_type=client_secret_basic; the user
 * selects client_registration and request_type (CONFORMANCE_VARIANT or the CI project).
 *
 * Every test starts the emulated OP (rp.start: what this module's OP does differently), makes the RP under test
 * log in against it (rp.driveClient), then follows the requests the RP sends. A request the OP must not see
 * fails the test from the endpoint (onUserinfoRequest); a request the RP may or must not send is awaited with
 * op.waitFor (upstream's waitTimeoutSeconds timer).
 *
 *   CONFORMANCE_PROJECT=rp-basic pnpm test tests/rp/basic.spec.ts
 */
import * as authz from "../../src/rp/authorization.ts";
import * as discovery from "../../src/rp/discovery.ts";
import * as idToken from "../../src/rp/id-token.ts";
import * as jwks from "../../src/rp/jwks.ts";
import { failTest } from "../../src/rp/op.ts";
import * as registration from "../../src/rp/registration.ts";
import * as userinfo from "../../src/rp/userinfo.ts";
import { test } from "../fixtures.ts";
import * as shared from "./shared.ts";

test.describe("oidcc-client-basic-certification-test-plan", () => {
	test.use({
		plan: {
			name: "oidcc-client-basic-certification-test-plan",
			variant: { response_type: "code", response_mode: "default", client_auth_type: "client_secret_basic" },
		},
	});

	// upstream: openid/client/OIDCCClientTest.java (rp-response_type-code)
	test("oidcc-client-test: the RP logs in with the code flow and calls the userinfo endpoint", async ({ rp }) => {
		// the module's emulated OP; the suite-vs-suite project serves the OP tests with the same one
		const op = await rp.start(shared.oidccClientTestOptions());
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		// upstream finishes the test after the userinfo request
		await op.expect("userinfo");
		await client;
	});

	// upstream: openid/client/OIDCCClientTestInvalidIssuerInIdToken.java (rp-id_token-issuer-mismatch)
	test("oidcc-client-test-invalid-iss: the RP rejects an id_token whose iss is not the issuer", async ({ rp }) => {
		const op = await rp.start({
			idTokenClaims: (claims) => idToken.addInvalidIssValueToIdToken(claims, "OIDCC-3.1.3.7"),
			onUserinfoRequest: () =>
				failTest(
					"Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid iss claim.",
				),
		});
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		// the RP must reject the id_token and stop: no userinfo request within waitTimeoutSeconds
		await op.waitFor("userinfo", rp.waitTimeoutSeconds);
		await client;
	});

	// upstream: openid/client/OIDCCClientTestMissingSubInIdToken.java (rp-id_token-sub)
	test("oidcc-client-test-missing-sub: the RP rejects an id_token without sub", async ({ rp }) => {
		const op = await rp.start({
			idTokenClaims: (claims) => idToken.removeSubFromIdToken(claims, "OIDCC-2"),
			onUserinfoRequest: () =>
				failTest("Client has incorrectly called userinfo_endpoint after receiving an id_token without a sub value."),
		});
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		// the RP must reject the id_token and stop: no userinfo request within waitTimeoutSeconds
		await op.waitFor("userinfo", rp.waitTimeoutSeconds);
		await client;
	});

	// upstream: openid/client/OIDCCClientTestInvalidAudInIdToken.java (rp-id_token-aud)
	test("oidcc-client-test-invalid-aud: the RP rejects an id_token whose aud is not its client_id", async ({ rp }) => {
		const op = await rp.start({
			idTokenClaims: (claims) => idToken.addInvalidAudValueToIdToken(claims, "OIDCC-3.1.3.7", "OIDCC-2"),
			onUserinfoRequest: () =>
				failTest(
					"Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid aud claim.",
				),
		});
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		// the RP must reject the id_token and stop: no userinfo request within waitTimeoutSeconds
		await op.waitFor("userinfo", rp.waitTimeoutSeconds);
		await client;
	});

	// upstream: openid/client/OIDCCClientTestMissingIatInIdToken.java (rp-id_token-iat)
	test("oidcc-client-test-missing-iat: the RP rejects an id_token without iat", async ({ rp }) => {
		const op = await rp.start({
			idTokenClaims: (claims) => idToken.removeIatFromIdToken(claims, "OIDCC-2"),
			onUserinfoRequest: () =>
				failTest("Client has incorrectly called userinfo_endpoint after receiving an id_token with no iat claim."),
		});
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		// the RP must reject the id_token and stop: no userinfo request within waitTimeoutSeconds
		await op.waitFor("userinfo", rp.waitTimeoutSeconds);
		await client;
	});

	// upstream: openid/client/OIDCCClientTestKidAbsentSingleJwks.java (rp-id_token-kid-absent-single-jwks)
	test("oidcc-client-test-kid-absent-single-jwks: the RP verifies an id_token without kid with the only matching key", async ({
		rp,
	}) => {
		const op = await rp.start({
			// without the unusable extra keys: the published JWKS must contain a single key of each type, without kid
			serverJwks: async () => {
				const keys = jwks.oidccGenerateServerJWKsSingleSigningKeyWithNoKeyId("OIDCC-10.1");
				await jwks.validateServerSigningKeys(keys);
				return keys;
			},
			signingAlg: () => idToken.setServerSigningAlgToRS256(),
		});
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		await op.expect("userinfo");
		await client;
	});

	// upstream: openid/client/OIDCCClientTestKidAbsentMultipleMatchingKeysInJwks.java (rp-id_token-kid-absent-multiple-jwks)
	test("oidcc-client-test-kid-absent-multiple-jwks: the RP rejects an id_token without kid or finds the key among several", async ({
		rp,
	}) => {
		const op = await rp.start({
			// without the unusable extra keys: the published JWKS must contain several possible keys, without kid
			serverJwks: async () => {
				const keys = jwks.oidccGenerateServerJWKsMultipleSigningsKeyWithNoKeyIds("OIDCC-10.1");
				await jwks.validateServerSigningKeys(keys);
				return keys;
			},
			// RS256 always: the test would not work with HS* or none
			signingAlg: () => idToken.setServerSigningAlgToRS256(),
		});
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		// both are fine: the RP rejects the id_token (no kid to pick the key by), or tries the keys and calls userinfo
		await op.waitFor("userinfo", rp.waitTimeoutSeconds);
		await client;
	});

	// upstream: openid/client/OIDCCClientTestIdTokenSignedUsingRS256.java (rp-id_token-sig-rs256)
	test("oidcc-client-test-idtoken-sig-rs256: the RP accepts an id_token signed with RS256", async ({ rp }) => {
		const op = await rp.start({
			serverConfiguration: discovery.oidccGenerateServerConfigurationIdTokenSigningAlgRS256Only,
			registrationSteps: (c) => registration.setClientIdTokenSignedResponseAlgToRS256(c),
			signingAlg: () => idToken.setServerSigningAlgToRS256("OIDCR-2"),
		});
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		await op.expect("userinfo");
		await client;
	});

	test.describe("code flow only", () => {
		test.skip(({ variant }) => variant.response_type !== "code", "not applicable unless response_type=code");

		// upstream: openid/client/OIDCCClientTestIdTokenSigAlgNone.java (rp-id_token-sig-none)
		test(
			"oidcc-client-test-idtoken-sig-none: the RP accepts an unsigned id_token from the token endpoint, or stops",
			shared.idTokenSigNone,
		);
	});

	// upstream: openid/client/OIDCCClientTestInvalidIdTokenSignatureWithRS256.java (rp-id_token-bad-sig-rs256)
	test("oidcc-client-test-invalid-sig-rs256: the RP rejects an id_token with an invalid RS256 signature", async ({
		rp,
	}) => {
		const op = await rp.start({
			serverConfiguration: discovery.oidccGenerateServerConfigurationIdTokenSigningAlgRS256Only,
			registrationSteps: (c) => registration.setClientIdTokenSignedResponseAlgToRS256(c),
			signingAlg: () => idToken.setServerSigningAlgToRS256(),
			idTokenSignature: (token) => idToken.invalidateIdTokenSignature(token, "OIDCC-3.1.3.7", "OIDCC-3.2.2.11"),
			// an id_token from the token endpoint (TLS) need not be validated (OIDCC-3.1.3.7 step 6)
			onUserinfoRequest: () =>
				rp.skipTest(
					"The client continued and called the userinfo endpoint after receiving an id token with an invalid signature from the token endpoint. This is acceptable as clients are not required to validate the signatures on id tokens received over a TLS protected connection.",
				),
		});
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		// the RP should reject the id_token and stop: no userinfo request within waitTimeoutSeconds
		await op.waitFor("userinfo", rp.waitTimeoutSeconds);
		await client;
	});

	test.describe("with an access token", () => {
		test.skip(({ variant }) => variant.response_type === "id_token", "not applicable to response_type=id_token");

		// upstream: openid/client/OIDCCClientTestInvalidSubInUserinfoResponse.java (rp-userinfo-bad-sub-claim)
		test("oidcc-client-test-userinfo-invalid-sub: the RP gets a userinfo response whose sub is not the id_token's (it must reject it)", async ({
			rp,
		}) => {
			const op = await rp.start({
				userinfo: (response) => userinfo.changeSubInUserInfoResponseToBeInvalid(response, "OIDCC-5.3.2"),
			});
			const client = rp.driveClient();
			await op.clientRegistered();
			await op.expect("authorization");
			await op.expect("token");
			// the suite cannot see whether the RP rejects the response: the test finishes after the userinfo request
			await op.expect("userinfo");
			await client;
		});
	});

	// upstream: openid/client/OIDCCClientTestNonceInvalid.java (rp-nonce-invalid)
	test("oidcc-client-test-nonce-invalid: the RP rejects an id_token whose nonce is not the one it sent", async ({
		rp,
	}) => {
		const op = await rp.start({
			idTokenClaims: (claims) => idToken.addInvalidNonceValueToIdToken(claims, "OIDCC-2"),
			onUserinfoRequest: () =>
				failTest(
					"Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid nonce value.",
				),
		});
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		// the RP must reject the id_token and stop: no userinfo request within waitTimeoutSeconds
		await op.waitFor("userinfo", rp.waitTimeoutSeconds);
		await client;
	});

	// upstream: openid/client/OIDCCClientTestScopeUserInfoClaims.java (rp-scope-userinfo-claims)
	test("oidcc-client-test-scope-userinfo-claims: the RP requests claims with the profile, email, phone or address scope", async ({
		rp,
	}) => {
		const op = await rp.start({
			checkAuthorizationRequest: (_params, scope) =>
				authz.ensureScopeContainsAtLeastOneOfProfileEmailPhoneAddress(scope),
			idTokenClaims: (claims, { responseType, userInfo, authorization }) => {
				// without an access token (response_type=id_token) the claims are returned in the id_token
				if (responseType.includesIdToken && !responseType.includesCode && !responseType.includesToken) {
					const claimsForScopes = userinfo.filterUserInfoForScopes(userInfo, authorization?.scope ?? "", "OIDCC-5.4");
					idToken.addUserinfoClaimsToIdTokenClaims(claims, claimsForScopes, "OIDCC-5.4");
				}
			},
		});
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("token");
		await op.expect("userinfo");
		await client;
	});

	test.describe("with a token endpoint", () => {
		test.skip(
			({ variant }) => variant.response_type === "id_token" || variant.response_type === "id_token token",
			"not applicable to response types without code",
		);

		// upstream: openid/client/OIDCCClientTestClientSecretBasic.java (rp-token_endpoint-client_secret_basic)
		test("oidcc-client-test-client-secret-basic: the RP authenticates at the token endpoint with client_secret_basic", async ({
			rp,
		}) => {
			// client_secret_basic whatever client authentication the configuration selects
			const op = await rp.start({ clientAuthType: "client_secret_basic" });
			const client = rp.driveClient();
			await op.clientRegistered();
			await op.expect("authorization");
			await op.expect("token");
			await op.expect("userinfo");
			await client;
		});
	});
});

/**
 * OpenID Connect Core: Hybrid Certification Profile, RP tests (upstream openid/client/OIDCCClientHybridTestPlan.java).
 *
 * Three module lists (upstream ModuleListEntry), one describe each, the tests of the profile document's table in its
 * order: response_type=code id_token, code token and code id_token token. All fix response_mode=default and
 * client_auth_type=client_secret_basic; the user selects client_registration and request_type (CONFORMANCE_VARIANT or
 * the CI project). A module in several lists runs once with each list's variant (the report keeps them apart).
 *
 * The emulated OP answers with the code and the id_token and/or access token in the fragment of the redirect; an
 * id_token from the authorization endpoint carries c_hash (and at_hash with an access token), which the RP must verify
 * before it exchanges the code. The bodies are in ./shared.ts.
 *
 *   CONFORMANCE_PROJECT=rp-hybrid pnpm test tests/rp/hybrid.spec.ts
 */
import { test } from "../fixtures.ts";
import * as shared from "./shared.ts";

const PLAN = "oidcc-client-hybrid-certification-test-plan";

test.describe(PLAN, () => {
	test.describe("response_type=code id_token", () => {
		test.use({
			plan: {
				name: PLAN,
				variant: { response_type: "code id_token", response_mode: "default", client_auth_type: "client_secret_basic" },
			},
		});

		// upstream: openid/client/OIDCCClientTest.java (rp-response_type-code+id_token)
		test(
			"oidcc-client-test: the RP logs in with response_type=code id_token and calls the userinfo endpoint",
			shared.oidccClientTest,
		);

		// upstream: openid/client/OIDCCClientTestInvalidIssuerInIdToken.java (rp-id_token-issuer-mismatch)
		test("oidcc-client-test-invalid-iss: the RP rejects an id_token whose iss is not the issuer", shared.invalidIss);

		// upstream: openid/client/OIDCCClientTestMissingSubInIdToken.java (rp-id_token-sub)
		test("oidcc-client-test-missing-sub: the RP rejects an id_token without sub", shared.missingSub);

		// upstream: openid/client/OIDCCClientTestInvalidAudInIdToken.java (rp-id_token-aud)
		test("oidcc-client-test-invalid-aud: the RP rejects an id_token whose aud is not its client_id", shared.invalidAud);

		// upstream: openid/client/OIDCCClientTestMissingIatInIdToken.java (rp-id_token-iat)
		test("oidcc-client-test-missing-iat: the RP rejects an id_token without iat", shared.missingIat);

		// upstream: openid/client/OIDCCClientTestKidAbsentSingleJwks.java (rp-id_token-kid-absent-single-jwks)
		test(
			"oidcc-client-test-kid-absent-single-jwks: the RP verifies an id_token without kid with the only matching key",
			shared.kidAbsentSingleJwks,
		);

		// upstream: openid/client/OIDCCClientTestKidAbsentMultipleMatchingKeysInJwks.java (rp-id_token-kid-absent-multiple-jwks)
		test(
			"oidcc-client-test-kid-absent-multiple-jwks: the RP rejects an id_token without kid or finds the key among several",
			shared.kidAbsentMultipleJwks,
		);

		// upstream: openid/client/OIDCCClientTestInvalidCHashInIdToken.java (rp-id_token-bad-c_hash)
		test(
			"oidcc-client-test-invalid-chash: the RP rejects an id_token whose c_hash does not match the code",
			shared.invalidCHash,
		);

		// upstream: openid/client/OIDCCClientTestMissingCHashInIdToken.java (rp-id_token-missing-c_hash)
		test(
			"oidcc-client-test-missing-chash: the RP rejects an id_token issued with a code but without c_hash",
			shared.missingCHash,
		);

		// upstream: openid/client/OIDCCClientTestIdTokenSignedUsingRS256.java (rp-id_token-sig-rs256)
		test("oidcc-client-test-idtoken-sig-rs256: the RP accepts an id_token signed with RS256", shared.idTokenSigRs256);

		// upstream: openid/client/OIDCCClientTestInvalidIdTokenSignatureWithRS256.java (rp-id_token-bad-sig-rs256)
		test(
			"oidcc-client-test-invalid-sig-rs256: the RP rejects an id_token with an invalid RS256 signature",
			shared.invalidSigRs256,
		);

		// upstream: openid/client/OIDCCClientTestInvalidSubInUserinfoResponse.java (rp-userinfo-bad-sub-claim)
		test(
			"oidcc-client-test-userinfo-invalid-sub: the RP gets a userinfo response whose sub is not the id_token's (it must reject it)",
			shared.userinfoInvalidSub,
		);

		// upstream: openid/client/OIDCCClientTestNonce.java (rp-nonce-unless-code-flow)
		test(
			"oidcc-client-test-nonce-unless-code-flow: the RP sends a nonce with the implicit and hybrid response types",
			shared.nonceUnlessCodeFlow,
		);

		// upstream: openid/client/OIDCCClientTestNonceInvalid.java (rp-nonce-invalid)
		test(
			"oidcc-client-test-nonce-invalid: the RP rejects an id_token whose nonce is not the one it sent",
			shared.nonceInvalid,
		);

		// upstream: openid/client/OIDCCClientTestScopeUserInfoClaims.java (rp-scope-userinfo-claims)
		test(
			"oidcc-client-test-scope-userinfo-claims: the RP requests claims with the profile, email, phone or address scope",
			shared.scopeUserinfoClaims,
		);

		// upstream: openid/client/OIDCCClientTestClientSecretBasic.java (rp-token_endpoint-client_secret_basic)
		test(
			"oidcc-client-test-client-secret-basic: the RP authenticates at the token endpoint with client_secret_basic",
			shared.clientSecretBasic,
		);
	});

	test.describe("response_type=code token", () => {
		test.use({
			plan: {
				name: PLAN,
				variant: { response_type: "code token", response_mode: "default", client_auth_type: "client_secret_basic" },
			},
		});

		// upstream: openid/client/OIDCCClientTest.java (rp-response_type-code+token)
		test(
			"oidcc-client-test: the RP logs in with response_type=code token and calls the userinfo endpoint",
			shared.oidccClientTest,
		);

		// upstream: openid/client/OIDCCClientTestInvalidIssuerInIdToken.java (rp-id_token-issuer-mismatch)
		test("oidcc-client-test-invalid-iss: the RP rejects an id_token whose iss is not the issuer", shared.invalidIss);

		// upstream: openid/client/OIDCCClientTestMissingSubInIdToken.java (rp-id_token-sub)
		test("oidcc-client-test-missing-sub: the RP rejects an id_token without sub", shared.missingSub);

		// upstream: openid/client/OIDCCClientTestInvalidAudInIdToken.java (rp-id_token-aud)
		test("oidcc-client-test-invalid-aud: the RP rejects an id_token whose aud is not its client_id", shared.invalidAud);

		// upstream: openid/client/OIDCCClientTestMissingIatInIdToken.java (rp-id_token-iat)
		test("oidcc-client-test-missing-iat: the RP rejects an id_token without iat", shared.missingIat);

		// upstream: openid/client/OIDCCClientTestKidAbsentSingleJwks.java (rp-id_token-kid-absent-single-jwks)
		test(
			"oidcc-client-test-kid-absent-single-jwks: the RP verifies an id_token without kid with the only matching key",
			shared.kidAbsentSingleJwks,
		);

		// upstream: openid/client/OIDCCClientTestKidAbsentMultipleMatchingKeysInJwks.java (rp-id_token-kid-absent-multiple-jwks)
		test(
			"oidcc-client-test-kid-absent-multiple-jwks: the RP rejects an id_token without kid or finds the key among several",
			shared.kidAbsentMultipleJwks,
		);

		// upstream: openid/client/OIDCCClientTestIdTokenSignedUsingRS256.java (rp-id_token-sig-rs256)
		test("oidcc-client-test-idtoken-sig-rs256: the RP accepts an id_token signed with RS256", shared.idTokenSigRs256);

		// upstream: openid/client/OIDCCClientTestInvalidIdTokenSignatureWithRS256.java (rp-id_token-bad-sig-rs256)
		test(
			"oidcc-client-test-invalid-sig-rs256: the RP rejects an id_token with an invalid RS256 signature",
			shared.invalidSigRs256,
		);

		// upstream: openid/client/OIDCCClientTestInvalidSubInUserinfoResponse.java (rp-userinfo-bad-sub-claim)
		test(
			"oidcc-client-test-userinfo-invalid-sub: the RP gets a userinfo response whose sub is not the id_token's (it must reject it)",
			shared.userinfoInvalidSub,
		);

		// upstream: openid/client/OIDCCClientTestNonce.java (rp-nonce-unless-code-flow)
		test(
			"oidcc-client-test-nonce-unless-code-flow: the RP sends a nonce with the implicit and hybrid response types",
			shared.nonceUnlessCodeFlow,
		);

		// upstream: openid/client/OIDCCClientTestNonceInvalid.java (rp-nonce-invalid)
		test(
			"oidcc-client-test-nonce-invalid: the RP rejects an id_token whose nonce is not the one it sent",
			shared.nonceInvalid,
		);

		// upstream: openid/client/OIDCCClientTestScopeUserInfoClaims.java (rp-scope-userinfo-claims)
		test(
			"oidcc-client-test-scope-userinfo-claims: the RP requests claims with the profile, email, phone or address scope",
			shared.scopeUserinfoClaims,
		);

		// upstream: openid/client/OIDCCClientTestClientSecretBasic.java (rp-token_endpoint-client_secret_basic)
		test(
			"oidcc-client-test-client-secret-basic: the RP authenticates at the token endpoint with client_secret_basic",
			shared.clientSecretBasic,
		);
	});

	test.describe("response_type=code id_token token", () => {
		test.use({
			plan: {
				name: PLAN,
				variant: {
					response_type: "code id_token token",
					response_mode: "default",
					client_auth_type: "client_secret_basic",
				},
			},
		});

		// upstream: openid/client/OIDCCClientTest.java (rp-response_type-code+id_token+token)
		test(
			"oidcc-client-test: the RP logs in with response_type=code id_token token and calls the userinfo endpoint",
			shared.oidccClientTest,
		);

		// upstream: openid/client/OIDCCClientTestInvalidIssuerInIdToken.java (rp-id_token-issuer-mismatch)
		test("oidcc-client-test-invalid-iss: the RP rejects an id_token whose iss is not the issuer", shared.invalidIss);

		// upstream: openid/client/OIDCCClientTestMissingSubInIdToken.java (rp-id_token-sub)
		test("oidcc-client-test-missing-sub: the RP rejects an id_token without sub", shared.missingSub);

		// upstream: openid/client/OIDCCClientTestInvalidAudInIdToken.java (rp-id_token-aud)
		test("oidcc-client-test-invalid-aud: the RP rejects an id_token whose aud is not its client_id", shared.invalidAud);

		// upstream: openid/client/OIDCCClientTestMissingIatInIdToken.java (rp-id_token-iat)
		test("oidcc-client-test-missing-iat: the RP rejects an id_token without iat", shared.missingIat);

		// upstream: openid/client/OIDCCClientTestKidAbsentSingleJwks.java (rp-id_token-kid-absent-single-jwks)
		test(
			"oidcc-client-test-kid-absent-single-jwks: the RP verifies an id_token without kid with the only matching key",
			shared.kidAbsentSingleJwks,
		);

		// upstream: openid/client/OIDCCClientTestKidAbsentMultipleMatchingKeysInJwks.java (rp-id_token-kid-absent-multiple-jwks)
		test(
			"oidcc-client-test-kid-absent-multiple-jwks: the RP rejects an id_token without kid or finds the key among several",
			shared.kidAbsentMultipleJwks,
		);

		// upstream: openid/client/OIDCCClientTestInvalidCHashInIdToken.java (rp-id_token-bad-c_hash)
		test(
			"oidcc-client-test-invalid-chash: the RP rejects an id_token whose c_hash does not match the code",
			shared.invalidCHash,
		);

		// upstream: openid/client/OIDCCClientTestMissingCHashInIdToken.java (rp-id_token-missing-c_hash)
		test(
			"oidcc-client-test-missing-chash: the RP rejects an id_token issued with a code but without c_hash",
			shared.missingCHash,
		);

		// upstream: openid/client/OIDCCClientTestInvalidAtHashInIdToken.java (rp-id_token-bad-at_hash)
		test(
			"oidcc-client-test-invalid-athash: the RP rejects an id_token whose at_hash does not match the access token",
			shared.invalidAtHash,
		);

		// upstream: openid/client/OIDCCClientTestMissingAtHashInIdToken.java (rp-id_token-missing-at_hash)
		test(
			"oidcc-client-test-missing-athash: the RP rejects an id_token issued with an access token but without at_hash",
			shared.missingAtHash,
		);

		// upstream: openid/client/OIDCCClientTestIdTokenSignedUsingRS256.java (rp-id_token-sig-rs256)
		test("oidcc-client-test-idtoken-sig-rs256: the RP accepts an id_token signed with RS256", shared.idTokenSigRs256);

		// upstream: openid/client/OIDCCClientTestInvalidIdTokenSignatureWithRS256.java (rp-id_token-bad-sig-rs256)
		test(
			"oidcc-client-test-invalid-sig-rs256: the RP rejects an id_token with an invalid RS256 signature",
			shared.invalidSigRs256,
		);

		// upstream: openid/client/OIDCCClientTestInvalidSubInUserinfoResponse.java (rp-userinfo-bad-sub-claim)
		test(
			"oidcc-client-test-userinfo-invalid-sub: the RP gets a userinfo response whose sub is not the id_token's (it must reject it)",
			shared.userinfoInvalidSub,
		);

		// upstream: openid/client/OIDCCClientTestNonce.java (rp-nonce-unless-code-flow)
		test(
			"oidcc-client-test-nonce-unless-code-flow: the RP sends a nonce with the implicit and hybrid response types",
			shared.nonceUnlessCodeFlow,
		);

		// upstream: openid/client/OIDCCClientTestNonceInvalid.java (rp-nonce-invalid)
		test(
			"oidcc-client-test-nonce-invalid: the RP rejects an id_token whose nonce is not the one it sent",
			shared.nonceInvalid,
		);

		// upstream: openid/client/OIDCCClientTestScopeUserInfoClaims.java (rp-scope-userinfo-claims)
		test(
			"oidcc-client-test-scope-userinfo-claims: the RP requests claims with the profile, email, phone or address scope",
			shared.scopeUserinfoClaims,
		);

		// upstream: openid/client/OIDCCClientTestClientSecretBasic.java (rp-token_endpoint-client_secret_basic)
		test(
			"oidcc-client-test-client-secret-basic: the RP authenticates at the token endpoint with client_secret_basic",
			shared.clientSecretBasic,
		);
	});
});

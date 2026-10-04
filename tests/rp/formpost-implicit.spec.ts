/**
 * OpenID Connect Core: Form Post Implicit Certification Profile, RP tests (upstream
 * openid/client/OIDCCClientFormPostImplicitTestPlan.java: the implicit plan's lists with response_mode=form_post,
 * AbstractFormPostTestPlan.changeResponseTypeToFormPost).
 *
 * Two module lists (upstream ModuleListEntry), one describe each, the tests of the profile document's table in its
 * order: response_type=id_token and response_type=id_token token. Both fix response_mode=form_post and
 * client_auth_type=client_secret_basic; the user selects client_registration and request_type (CONFORMANCE_VARIANT or
 * the CI project). A module in both lists runs once with each list's variant (the report keeps them apart).
 *
 * The emulated OP answers with the id_token (and the access token) in a form the browser posts to the redirect_uri:
 * the RP must verify it there, it has no token endpoint to call. With response_type=id_token there is no access token
 * either: a module finishes once the RP fetched the OP's keys to verify the id_token (upstream
 * finishTestIfAllRequestsAreReceived). The bodies are in ./shared.ts.
 *
 *   CONFORMANCE_PROJECT=rp-formpost-implicit pnpm test tests/rp/formpost-implicit.spec.ts
 */
import { test } from "../fixtures.ts";
import * as shared from "./shared.ts";

const PLAN = "oidcc-client-formpost-implicit-certification-test-plan";

test.describe(PLAN, () => {
	test.describe("response_type=id_token", () => {
		test.use({
			plan: {
				name: PLAN,
				variant: { response_type: "id_token", response_mode: "form_post", client_auth_type: "client_secret_basic" },
			},
		});

		// upstream: openid/client/OIDCCClientTest.java (rp-response_type-id_token)
		test(
			"oidcc-client-test: the RP logs in with response_type=id_token and verifies the id_token with the OP's keys",
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
	});

	test.describe("response_type=id_token token", () => {
		test.use({
			plan: {
				name: PLAN,
				variant: {
					response_type: "id_token token",
					response_mode: "form_post",
					client_auth_type: "client_secret_basic",
				},
			},
		});

		// upstream: openid/client/OIDCCClientTest.java (rp-response_type-id_token+token)
		test(
			"oidcc-client-test: the RP logs in with response_type=id_token token and calls the userinfo endpoint",
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
	});
});

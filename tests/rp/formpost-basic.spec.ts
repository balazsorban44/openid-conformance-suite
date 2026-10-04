/**
 * OpenID Connect Core: Form Post Basic Certification Profile, RP tests (upstream
 * openid/client/OIDCCClientFormPostBasicTestPlan.java: the basic plan's list with response_mode=form_post,
 * AbstractFormPostTestPlan.changeResponseTypeToFormPost).
 *
 * The plan fixes response_type=code, response_mode=form_post and client_auth_type=client_secret_basic; the user
 * selects client_registration and request_type (CONFORMANCE_VARIANT or the CI project). The emulated OP answers the
 * authorization request with a page that posts the code to the RP's redirect_uri. The modules are the basic plan's
 * (tests/rp/basic.spec.ts); their bodies are in ./shared.ts.
 *
 *   CONFORMANCE_PROJECT=rp-formpost-basic pnpm test tests/rp/formpost-basic.spec.ts
 */
import { selectedVariant, test, variantNotApplicable } from "../fixtures.ts";
import * as shared from "./shared.ts";

test.describe("oidcc-client-formpost-basic-certification-test-plan", () => {
	const plan = {
		name: "oidcc-client-formpost-basic-certification-test-plan",
		variant: { response_type: "code", response_mode: "form_post", client_auth_type: "client_secret_basic" },
	};
	test.use({ plan });

	// upstream: openid/client/OIDCCClientTest.java (rp-response_type-code)
	test("oidcc-client-test: the RP logs in with the code flow and calls the userinfo endpoint", shared.oidccClientTest);

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

	// the plan has this module for the code flow only
	if (selectedVariant(plan).response_type === "code") {
		// upstream: openid/client/OIDCCClientTestIdTokenSigAlgNone.java (rp-id_token-sig-none)
		test(
			"oidcc-client-test-idtoken-sig-none: the RP accepts an unsigned id_token from the token endpoint, or stops",
			shared.idTokenSigNone,
		);
	}

	// upstream: openid/client/OIDCCClientTestInvalidIdTokenSignatureWithRS256.java (rp-id_token-bad-sig-rs256)
	test(
		"oidcc-client-test-invalid-sig-rs256: the RP rejects an id_token with an invalid RS256 signature",
		shared.invalidSigRs256,
	);

	// upstream @VariantNotApplicable(parameter = ResponseType.class, values = { "id_token" }): no access token, no userinfo
	if (!variantNotApplicable(plan, { response_type: ["id_token"] })) {
		// upstream: openid/client/OIDCCClientTestInvalidSubInUserinfoResponse.java (rp-userinfo-bad-sub-claim)
		test(
			"oidcc-client-test-userinfo-invalid-sub: the RP gets a userinfo response whose sub is not the id_token's (it must reject it)",
			shared.userinfoInvalidSub,
		);
	}

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

	// the plan has this module for the response types with a token endpoint request only
	if (!variantNotApplicable(plan, { response_type: ["id_token", "id_token token"] })) {
		// upstream: openid/client/OIDCCClientTestClientSecretBasic.java (rp-token_endpoint-client_secret_basic)
		test(
			"oidcc-client-test-client-secret-basic: the RP authenticates at the token endpoint with client_secret_basic",
			shared.clientSecretBasic,
		);
	}
});

/**
 * FAPI 2.0 Security Profile Final: Relying Party (client) test (upstream fapi2spfinal/FAPI2SPFinalClientTestPlan.java).
 *
 * The plan fixes fapi_request_method=unsigned and fapi_response_mode=plain_response; the user selects
 * client_auth_type, sender_constrain, fapi_profile, fapi_client_type, authorization_request_type and grant_management
 * (CONFORMANCE_VARIANT or the CI project). The modules are the message signing plan's without the eight JARM ones.
 * Ported variants: client_auth_type=private_key_jwt, sender_constrain=dpop, fapi_profile=plain_fapi,
 * fapi_client_type oidc / plain_oauth, authorization_request_type=simple, grant_management=disabled (mTLS is not
 * covered: the emulated authorization server has no mTLS listener).
 *
 * Every test starts the emulated FAPI 2 authorization server (rp.startFapi2: what this module's server does
 * differently), makes the RP under test log in against it (rp.driveClient), then follows the requests the RP sends
 * (PAR, authorization, token, the accounts resource; a use_dpop_nonce challenge is answered first by the PAR, token and
 * resource endpoints). A request the RP must not send is refused and fails the test; the modules' bodies are in
 * ./fapi2-shared.ts.
 *
 *   CONFORMANCE_PROJECT=rp-fapi2-security-profile pnpm test tests/rp/fapi2-security-profile.spec.ts
 */
import { test, variantNotApplicable } from "../fixtures.ts";
import * as shared from "./fapi2-shared.ts";

test.describe("fapi2-security-profile-final-client-test-plan", () => {
	const plan = {
		name: "fapi2-security-profile-final-client-test-plan",
		variant: { fapi_request_method: "unsigned", fapi_response_mode: "plain_response" },
	};
	test.use({ plan });
	const plainOauth = variantNotApplicable(plan, { fapi_client_type: ["plain_oauth"] });
	const clientCredentialsGrant = variantNotApplicable(plan, { fapi_profile: ["fapi_client_credentials_grant"] });
	const mtlsSenderConstrain = variantNotApplicable(plan, { sender_constrain: ["mtls"] });

	// upstream: fapi2spfinal/FAPI2SPFinalClientTestHappyPath.java
	test(
		"fapi2-security-profile-final-client-test-happy-path: the RP pushes its request, exchanges the code with a DPoP proof and calls the resource with the DPoP-bound token",
		shared.happyPath,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalClientTestDiscoveryIssuerMismatch.java
	if (!clientCredentialsGrant) {
		test(
			"fapi2-security-profile-final-client-test-discovery-issuer-mismatch: the RP stops when the discovery document's issuer is not the url it came from",
			shared.discoveryIssuerMismatch,
		);
	}

	// the id_token modules are OpenID Connect only (upstream @VariantNotApplicable fapi_client_type=plain_oauth)
	if (!plainOauth && !clientCredentialsGrant) {
		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidIss.java
		test(
			"fapi2-security-profile-final-client-test-invalid-iss: the RP rejects an id_token whose iss is not the issuer and stops",
			shared.invalidIss,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidAud.java
		test(
			"fapi2-security-profile-final-client-test-invalid-aud: the RP rejects an id_token whose aud is not its client_id and stops",
			shared.invalidAud,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidSecondaryAud.java
		test(
			"fapi2-security-profile-final-client-test-invalid-secondary-aud: the RP rejects an id_token whose aud array has an untrusted value and stops",
			shared.invalidSecondaryAud,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidNullAlg.java
		test(
			"fapi2-security-profile-final-client-test-invalid-null-alg: the RP rejects an unsigned (alg none) id_token and stops",
			shared.invalidNullAlg,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidAlternateAlg.java
		test(
			"fapi2-security-profile-final-client-test-invalid-alternate-alg: the RP rejects an id_token signed with RS256 and stops",
			shared.invalidAlternateAlg,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidExpiredExp.java
		test(
			"fapi2-security-profile-final-client-test-invalid-expired-exp: the RP rejects an expired id_token and stops",
			shared.invalidExpiredExp,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidMissingExp.java
		test(
			"fapi2-security-profile-final-client-test-invalid-missing-exp: the RP rejects an id_token without exp and stops",
			shared.invalidMissingExp,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidMissingAud.java
		test(
			"fapi2-security-profile-final-client-test-invalid-missing-aud: the RP rejects an id_token without aud and stops",
			shared.invalidMissingAud,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidMissingIss.java
		test(
			"fapi2-security-profile-final-client-test-invalid-missing-iss: the RP rejects an id_token without iss and stops",
			shared.invalidMissingIss,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestValidAudAsArray.java
		test(
			"fapi2-security-profile-final-client-test-valid-aud-as-array: the RP accepts an id_token whose aud is an array with its client_id",
			shared.validAudAsArray,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidNonce.java
		test(
			"fapi2-security-profile-final-client-test-invalid-nonce: the RP rejects an id_token whose nonce is not the one it sent and stops",
			shared.invalidNonce,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidMissingNonce.java
		test(
			"fapi2-security-profile-final-client-test-invalid-missing-nonce: the RP rejects an id_token without the nonce it sent and stops (skipped when it sent none)",
			shared.invalidMissingNonce,
		);
	}

	// the iss modules do not apply to JARM (upstream @VariantNotApplicable fapi_response_mode=jarm)
	if (!clientCredentialsGrant) {
		// upstream: fapi2spfinal/FAPI2SPFinalClientTestInvalidAuthorizationResponseIss.java
		test(
			"fapi2-security-profile-final-client-test-invalid-authorization-response-iss: the RP rejects an authorization response whose iss is not the issuer and stops",
			shared.invalidAuthorizationResponseIss,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestRemoveAuthorizationResponseIss.java
		test(
			"fapi2-security-profile-final-client-test-remove-authorization-response-iss: the RP rejects an authorization response without iss and stops",
			shared.removeAuthorizationResponseIss,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestEnsureAuthorizationResponseWithInvalidStateFails.java
		test(
			"fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-state-fails: the RP rejects an authorization response whose state is not the one it sent and stops",
			shared.invalidState,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestEnsureAuthorizationResponseWithInvalidMissingStateFails.java
		test(
			"fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-missing-state-fails: the RP rejects an authorization response without the state it sent and stops (skipped when it sent none)",
			shared.missingState,
		);

		// upstream: fapi2spfinal/FAPI2SPFinalClientTestTokenEndpointResponseWithoutExpiresIn.java
		test(
			"fapi2-security-profile-final-client-test-token-endpoint-response-without-expires_in: the RP completes the flow with a token response without expires_in",
			shared.tokenEndpointResponseWithoutExpiresIn,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalClientTestTokenTypeCaseInsenstivity.java
	test(
		"fapi2-security-profile-final-client-test-token-type-case-insensitivity: the RP accepts a token_type in another case (dpOp)",
		shared.tokenTypeCaseInsensitivity,
	);

	if (!mtlsSenderConstrain && !clientCredentialsGrant) {
		// upstream: fapi2spfinal/FAPI2SPFinalClientTestRSDpopAuthSchemeCaseInsenstivity.java
		test(
			"fapi2-security-profile-final-client-test-rs-dpop-auth-scheme-case-insensitivity: the RP repeats the resource request after a use_dpop_nonce challenge whose scheme is dPoP",
			shared.rsDpopAuthSchemeCaseInsensitivity,
		);
	}

	if (!mtlsSenderConstrain) {
		// upstream: fapi2spfinal/FAPI2SPFinalClientTestHappyPathNoDpopNonce.java
		test(
			"fapi2-security-profile-final-client-test-happy-path-no-dpop-nonce: the RP completes the flow against a server that requires no DPoP nonce",
			shared.happyPathNoDpopNonce,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases.java
	test(
		"fapi2-security-profile-final-client-test-happy-path-no-mtls-endpoint-aliases: the RP completes the flow against a server that publishes no mtls_endpoint_aliases",
		shared.happyPathNoMtlsEndpointAliases,
	);

	// TODO(port): fapi2spfinal/FAPI2SPFinalClientRefreshTokenTest.java (not applicable to plain_fapi, the only
	// profile the emulated authorization server implements: Brazil, CBUAE, Chile and KSA only)
	// TODO(port): fapi2spfinal/FAPI2SPFinalClientTestGrantManagementHappyPath.java,
	// FAPI2SPFinalClientTestGrantManagementQueryAndRevoke.java, FAPI2SPFinalClientTestGrantManagementInvalidGrantIdFails.java
	// (grant_management=enabled is not ported; they are not applicable with grant_management=disabled)
});

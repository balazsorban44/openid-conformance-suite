/**
 * FAPI 2.0 Message Signing Final: Authorization server test (upstream
 * fapi2spfinal/FAPI2MessageSigningFinalTestPlan.java).
 *
 * The user selects every FAPI 2 variant parameter (CONFORMANCE_VARIANT or the CI project): the security profile
 * plan's plus fapi_request_method (unsigned, signed_non_repudiation) and fapi_response_mode (plain_response, jarm).
 * Ported variants: client_auth_type=private_key_jwt, sender_constrain=dpop, fapi_profile=plain_fapi,
 * authorization_request_type=simple, grant_management=disabled.
 *
 *   CONFORMANCE_PROJECT=fapi2-message-signing pnpm test tests/fapi2/message-signing.spec.ts
 *   CONFORMANCE_PROJECT=fapi2-message-signing-jarm pnpm test tests/fapi2/message-signing.spec.ts
 */
import { test, variantNotApplicable } from "../fixtures.ts";
import {
	fapi2AccessTokenTypeHeaderCaseSensitivity,
	fapi2AttemptReuseAuthorizationCodeAfterOneSecond,
	fapi2DiscoveryEndpointVerification,
	fapi2EnsureAuthorizationCodeIsBoundToClient,
	fapi2EnsureAuthorizationRequestWithoutNonceSuccess,
	fapi2EnsureAuthorizationRequestWithoutStateSuccess,
	fapi2EnsureClientAssertionInTokenEndpoint,
	fapi2EnsureClientIdInTokenEndpoint,
	fapi2EnsureExpiredRequestObjectFails,
	fapi2EnsureHolderOfKeyRequired,
	fapi2EnsureInvalidClientAssertionsFail,
	fapi2EnsureMismatchedDpopJktFails,
	fapi2EnsureOtherScopeOrderSucceeds,
	fapi2EnsureRequestObjectWithoutExpFails,
	fapi2EnsureServerAcceptsRequestObjectWithMultipleAud,
	fapi2HappyFlow,
	fapi2PAREnsurePKCERequired,
	fapi2ParWithoutDuplicateParameters,
	fapi2RefreshToken,
} from "./shared.ts";

test.describe("fapi2-message-signing-final-test-plan", () => {
	const plan = { name: "fapi2-message-signing-final-test-plan", variant: {} };
	test.use({ plan });
	const plainOauth = variantNotApplicable(plan, { openid: ["plain_oauth"] });
	const unsigned = variantNotApplicable(plan, { fapi_request_method: ["unsigned"] });
	const mtlsSenderConstrain = variantNotApplicable(plan, { sender_constrain: ["mtls"] });
	const notPrivateKeyJwt = variantNotApplicable(plan, { client_auth_type: ["mtls", "client_attestation"] });

	// upstream: fapi2spfinal/FAPI2SPFinalDiscoveryEndpointVerification.java
	test(
		"fapi2-security-profile-final-discovery-end-point-verification: the discovery document has what FAPI 2.0 requires (PAR, PKCE S256, the signing algorithms, private_key_jwt, iss or JARM in the response)",
		fapi2DiscoveryEndpointVerification,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalHappyFlow.java
	test(
		"fapi2-security-profile-final-happy-flow: two clients complete the PAR, DPoP-bound code flow (signed request objects, JARM per the variant) and the resource rejects the other client's key",
		fapi2HappyFlow,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureServerAcceptsRequestObjectWithMultipleAud.java
	if (!unsigned) {
		test(
			"fapi2-security-profile-final-ensure-request-object-with-multiple-aud-succeeds: a request object whose aud array contains the issuer among other values is accepted",
			fapi2EnsureServerAcceptsRequestObjectWithMultipleAud,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureAuthorizationRequestWithoutStateSuccess.java
	test(
		"fapi2-security-profile-final-ensure-authorization-request-without-state-success: a request without state succeeds and the response carries no state",
		fapi2EnsureAuthorizationRequestWithoutStateSuccess,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureAuthorizationRequestWithoutNonceSuccess.java
	if (!plainOauth) {
		test(
			"fapi2-security-profile-final-ensure-authorization-request-without-nonce-success: a code flow request without nonce succeeds",
			fapi2EnsureAuthorizationRequestWithoutNonceSuccess,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureOtherScopeOrderSucceeds.java
	if (!plainOauth) {
		test(
			"fapi2-security-profile-final-ensure-other-scope-order-succeeds: the scopes in another order are accepted",
			fapi2EnsureOtherScopeOrderSucceeds,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalAccessTokenTypeHeaderCaseSensitivity.java
	test(
		"fapi2-security-profile-final-access-token-type-header-case-sensitivity: the resource accepts the token type in another case",
		fapi2AccessTokenTypeHeaderCaseSensitivity,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureMismatchedDpopJktFails.java
	if (!mtlsSenderConstrain) {
		test(
			"fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails: a dpop_jkt that does not match the PAR request's DPoP proof is rejected",
			fapi2EnsureMismatchedDpopJktFails,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectWithoutExpFails.java
	if (!unsigned) {
		test(
			"fapi2-security-profile-final-ensure-request-object-without-exp-fails: a request object without exp is rejected at the PAR or the authorization endpoint",
			fapi2EnsureRequestObjectWithoutExpFails,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureExpiredRequestObjectFails.java
	if (!unsigned) {
		test(
			"fapi2-security-profile-final-ensure-expired-request-object-fails: an expired request object is rejected at the PAR or the authorization endpoint",
			fapi2EnsureExpiredRequestObjectFails,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureClientIdInTokenEndpoint.java
	test(
		"fapi2-security-profile-final-ensure-client-id-in-token-endpoint: the second client's id with the first client's key is refused at the token endpoint",
		fapi2EnsureClientIdInTokenEndpoint,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureHolderOfKeyRequired.java
	test(
		"fapi2-security-profile-final-ensure-holder-of-key-required: a token request without a DPoP proof is rejected",
		fapi2EnsureHolderOfKeyRequired,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureAuthorizationCodeIsBoundToClient.java
	test(
		"fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client: another client cannot redeem the code",
		fapi2EnsureAuthorizationCodeIsBoundToClient,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalAttemptReuseAuthorizationCodeAfterOneSecond.java
	test(
		"fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second: reusing the code fails with invalid_grant and should revoke the access token",
		fapi2AttemptReuseAuthorizationCodeAfterOneSecond,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureClientAssertionInTokenEndpoint.java
	if (!notPrivateKeyJwt) {
		test(
			"fapi2-security-profile-final-ensure-client-assertion-in-token-endpoint: a token request without a client assertion is rejected",
			fapi2EnsureClientAssertionInTokenEndpoint,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureInvalidClientAssertionsFail.java
	if (!notPrivateKeyJwt) {
		test(
			"fapi2-security-profile-final-ensure-invalid-client-assertions-fail: every invalid client assertion is rejected at the PAR endpoint and a valid one accepted",
			fapi2EnsureInvalidClientAssertionsFail,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalRefreshToken.java
	test(
		"fapi2-security-profile-final-refresh-token: refresh tokens work for both clients, require client authentication and the DPoP proof, and are bound to the client",
		fapi2RefreshToken,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalPAREnsurePKCERequired.java
	test(
		"fapi2-security-profile-final-par-ensure-pkce-required: a PAR request without PKCE is rejected at the PAR or the authorization endpoint",
		fapi2PAREnsurePKCERequired,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalParWithoutDuplicateParameters.java
	test(
		"fapi2-security-profile-final-par-without-duplicate-parameters: the authorization request with only client_id and request_uri succeeds",
		fapi2ParWithoutDuplicateParameters,
	);

	// TODO(port): FAPI2SPFinalUserRejectsAuthentication.java
	// TODO(port): FAPI2SPFinalEnsureAuthorizationRequestWith64CharNonceSuccess.java
	// TODO(port): FAPI2SPFinalTestClaimsParameterIdentityClaims.java
	// TODO(port): FAPI2SPFinalEnsureRequestObjectWithNbf8SecondsInTheFutureIsAccepted.java
	// TODO(port): FAPI2SPFinalCheckDpopProofNbfExp.java
	// TODO(port): FAPI2SPFinalEnsureDpopProofWithIat10SecondsBeforeSucceeds.java
	// TODO(port): FAPI2SPFinalEnsureDpopProofWithIat10SecondsAfterSucceeds.java
	// TODO(port): FAPI2SPFinalEnsureTokenEndpointFailsWithMismatchedDpopProofJkt.java
	// TODO(port): FAPI2SPFinalEnsureTokenEndpointFailsWithMismatchedDpopJkt.java
	// TODO(port): FAPI2SPFinalEnsureDpopProofAtParEndpointBindingSuccess.java
	// TODO(port): FAPI2SPFinalEnsureDpopAuthCodeBindingSuccess.java
	// TODO(port): FAPI2SPFinalEnsureDifferentNonceInsideAndOutsideRequestObject.java
	// TODO(port): FAPI2SPFinalEnsureDifferentStateInsideAndOutsideRequestObject.java
	// TODO(port): FAPI2SPFinalEnsureAuthorizationRequestWithLongNonce.java
	// TODO(port): FAPI2SPFinalEnsureAuthorizationRequestWithLongState.java
	// TODO(port): FAPI2SPFinalEnsureRequestObjectWithoutNbfFails.java
	// TODO(port): FAPI2SPFinalStateOnlyOutsideRequestObjectNotUsed.java
	// TODO(port): FAPI2SPFinalEnsureRequestObjectWithoutRedirectUriFails.java
	// TODO(port): FAPI2SPFinalEnsureRequestObjectWithBadAudFails.java
	// TODO(port): FAPI2SPFinalEnsureRequestObjectWithExpOver60Fails.java
	// TODO(port): FAPI2SPFinalAustraliaConnectIdRequestObjectWithExpOver10Fails.java (fapi_profile=connectid_au only)
	// TODO(port): FAPI2SPFinalEnsureRequestObjectWithNbfOver60Fails.java
	// TODO(port): FAPI2SPFinalAustraliaConnectIdEnsureRequestObjectWithNbfOver15Fails.java (fapi_profile=connectid_au only)
	// TODO(port): FAPI2SPFinalKsaEnsureRequestObjectWithExpOver10Fails.java (fapi_profile=ksa only)
	// TODO(port): FAPI2SPFinalKsaEnsureRequestObjectWithNbfOver10Fails.java (fapi_profile=ksa only)
	// TODO(port): FAPI2SPFinalEnsureSignedRequestObjectWithRS256Fails.java
	// TODO(port): FAPI2SPFinalEnsureRequestObjectSignatureAlgorithmIsNotNone.java
	// TODO(port): FAPI2SPFinalEnsureRequestObjectWithInvalidSignatureFails.java
	// TODO(port): FAPI2SPFinalEnsureMatchingKeyInAuthorizationRequest.java
	// TODO(port): FAPI2SPFinalEnsureUnsignedRequestAtParEndpointFails.java
	// TODO(port): FAPI2SPFinalEnsureRegisteredRedirectUri.java (not applicable to fapi_profile=plain_fapi)
	// TODO(port): FAPI2SPFinalTolerateUnregisteredRedirectUri.java
	// TODO(port): FAPI2SPFinalEnsureUnsignedAuthorizationRequestWithoutUsingParFails.java
	// TODO(port): FAPI2SPFinalEnsureRedirectUriInAuthorizationRequest.java
	// TODO(port): FAPI2SPFinalEnsureResponseTypeCodeIdTokenFails.java
	// TODO(port): FAPI2SPFinalAustraliaConnectIdEnsureInvalidPurposeFails.java (fapi_profile=connectid_au only)
	// TODO(port): FAPI2SPFinalEnsureResponseTypeTokenFails.java
	// TODO(port): FAPI2SPFinalAttemptToUseExpiredAuthCode.java
	// TODO(port): FAPI2SPFinalEnsureSignedClientAssertionWithRS256Fails.java
	// TODO(port): FAPI2SPFinalEnsureClientAssertionWithExpIs5MinutesInPastFails.java
	// TODO(port): FAPI2SPFinalEnsureClientAssertionWithWrongAudFails.java
	// TODO(port): FAPI2SPFinalEnsureClientAssertionWithNoSubFails.java
	// TODO(port): FAPI2SPFinalDpopNegativeTests.java
	// TODO(port): FAPI2SPFinalCdrEnsureSharingDurationZeroGivesNoRefreshToken.java (fapi_profile=consumerdataright_au only)
	// TODO(port): FAPI2SPFinalCdrEnsureNegativeSharingDurationFails.java (fapi_profile=consumerdataright_au only)
	// TODO(port): FAPI2SPFinalCdrRefreshTokenIntrospectionExpiry.java (fapi_profile=consumerdataright_au only)
	// TODO(port): FAPI2SPFinalCdrArrangementAmendmentRevokesOldTokens.java (fapi_profile=consumerdataright_au only)
	// TODO(port): FAPI2SPFinalCdrEnsureUnrecognisedArrangementIdFails.java (fapi_profile=consumerdataright_au only)
	// TODO(port): FAPI2SPFinalBrazilEnsureBadPaymentSignatureFails.java (fapi_profile=openbanking_brazil only)
	// TODO(port): FAPI2SPFinalAustraliaConnectIdTestClaimsParameterIdTokenIdentityClaims.java (fapi_profile=connectid_au only)
	// TODO(port): FAPI2SPFinalPAREnsureServerAcceptsReusedRequestUriBeforeAuthenticationCompletion.java
	// TODO(port): FAPI2SPFinalPARAttemptReuseRequestUri.java
	// TODO(port): FAPI2SPFinalPARAttemptToUseExpiredRequestUri.java
	// TODO(port): FAPI2SPFinalPAREnsureRequestUriIsBoundToClient.java
	// TODO(port): FAPI2SPFinalPARRejectRequestUriInParAuthorizationFormParams.java
	// TODO(port): FAPI2SPFinalPARRejectInvalidHttpVerb.java
	// TODO(port): FAPI2SPFinalPAREnsurePKCECodeVerifierRequired.java
	// TODO(port): FAPI2SPFinalPARIncorrectPKCECodeVerifierRejected.java
	// TODO(port): FAPI2SPFinalPAREnsurePlainPKCERejected.java
	// TODO(port): FAPI2SPFinalPARRejectRequestUriInParAuthorizationRequest.java
	// TODO(port): FAPI2SPFinalGrantManagementQueryAndRevoke.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementMerge.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementReplace.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementEnsureInvalidGrantIdFails.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementEnsureQueryNonExistentGrantFails.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementEnsureWrongClientCannotQueryGrant.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementEnsureWrongClientCannotRevokeGrant.java (grant_management=enabled only)
});

/**
 * FAPI 2.0 Security Profile Final: Authorization server test (upstream fapi2spfinal/FAPI2SPFinalTestPlan.java).
 *
 * The plan fixes fapi_request_method=unsigned and fapi_response_mode=plain_response; the user selects
 * client_auth_type, sender_constrain, fapi_profile, openid, authorization_request_type and grant_management
 * (CONFORMANCE_VARIANT or the CI project). The modules are the message signing plan's without the signed request
 * object ones. Ported variants: client_auth_type=private_key_jwt, sender_constrain=dpop, fapi_profile=plain_fapi,
 * authorization_request_type=simple, grant_management=disabled.
 *
 *   CONFORMANCE_PROJECT=fapi2-security-profile pnpm test tests/fapi2/security-profile.spec.ts
 */
import { test, variantNotApplicable } from "../fixtures.ts";
import {
	fapi2AccessTokenTypeHeaderCaseSensitivity,
	fapi2AttemptReuseAuthorizationCodeAfterOneSecond,
	fapi2AttemptToUseExpiredAuthCode,
	fapi2CheckDpopProofNbfExp,
	fapi2DiscoveryEndpointVerification,
	fapi2DpopNegativeTests,
	fapi2EnsureAuthorizationCodeIsBoundToClient,
	fapi2EnsureAuthorizationRequestWith64CharNonceSuccess,
	fapi2EnsureAuthorizationRequestWithLongNonce,
	fapi2EnsureAuthorizationRequestWithLongState,
	fapi2EnsureAuthorizationRequestWithoutNonceSuccess,
	fapi2EnsureAuthorizationRequestWithoutStateSuccess,
	fapi2EnsureClientAssertionInTokenEndpoint,
	fapi2EnsureClientAssertionWithExpIs5MinutesInPastFails,
	fapi2EnsureClientAssertionWithNoSubFails,
	fapi2EnsureClientAssertionWithWrongAudFails,
	fapi2EnsureClientIdInTokenEndpoint,
	fapi2EnsureDifferentNonceInsideAndOutsideRequestObject,
	fapi2EnsureDifferentStateInsideAndOutsideRequestObject,
	fapi2EnsureDpopAuthCodeBindingSuccess,
	fapi2EnsureDpopProofAtParEndpointBindingSuccess,
	fapi2EnsureDpopProofWithIat10SecondsAfterSucceeds,
	fapi2EnsureDpopProofWithIat10SecondsBeforeSucceeds,
	fapi2EnsureHolderOfKeyRequired,
	fapi2EnsureInvalidClientAssertionsFail,
	fapi2EnsureMismatchedDpopJktFails,
	fapi2EnsureOtherScopeOrderSucceeds,
	fapi2EnsureRequestObjectWithoutRedirectUriFails,
	fapi2EnsureRedirectUriInAuthorizationRequest,
	fapi2EnsureRegisteredRedirectUri,
	fapi2EnsureResponseTypeCodeIdTokenFails,
	fapi2EnsureResponseTypeTokenFails,
	fapi2EnsureSignedClientAssertionWithRS256Fails,
	fapi2EnsureTokenEndpointFailsWithMismatchedDpopJkt,
	fapi2EnsureTokenEndpointFailsWithMismatchedDpopProofJkt,
	fapi2EnsureUnsignedAuthorizationRequestWithoutUsingParFails,
	fapi2HappyFlow,
	fapi2PARAttemptReuseRequestUri,
	fapi2PARAttemptToUseExpiredRequestUri,
	fapi2PAREnsurePKCECodeVerifierRequired,
	fapi2PAREnsurePKCERequired,
	fapi2PAREnsurePlainPKCERejected,
	fapi2PAREnsureRequestUriIsBoundToClient,
	fapi2PAREnsureServerAcceptsReusedRequestUriBeforeAuthenticationCompletion,
	fapi2PARIncorrectPKCECodeVerifierRejected,
	fapi2PARRejectInvalidHttpVerb,
	fapi2PARRejectRequestUriInParAuthorizationFormParams,
	fapi2ParWithoutDuplicateParameters,
	fapi2RefreshToken,
	fapi2StateOnlyOutsideRequestObjectNotUsed,
	fapi2TestClaimsParameterIdentityClaims,
	fapi2TolerateUnregisteredRedirectUri,
	fapi2UserRejectsAuthentication,
} from "./shared.ts";

test.describe("fapi2-security-profile-final-test-plan", () => {
	const plan = {
		name: "fapi2-security-profile-final-test-plan",
		variant: { fapi_request_method: "unsigned", fapi_response_mode: "plain_response" },
	};
	test.use({ plan });
	const plainOauth = variantNotApplicable(plan, { openid: ["plain_oauth"] });
	const mtlsSenderConstrain = variantNotApplicable(plan, { sender_constrain: ["mtls"] });
	const notPrivateKeyJwt = variantNotApplicable(plan, { client_auth_type: ["mtls", "client_attestation"] });
	// The 'redirect_uri' is required to be pre-registered. This is not the case for 'plain_fapi'.
	const plainFapi = variantNotApplicable(plan, { fapi_profile: ["plain_fapi", "fapi_client_credentials_grant"] });
	const registeredRedirectUriProfile = variantNotApplicable(plan, {
		fapi_profile: [
			"consumerdataright_au",
			"openbanking_brazil",
			"connectid_au",
			"cbuae",
			"ksa",
			"openbanking_chile",
			"fapi_client_credentials_grant",
		],
	});

	// upstream: fapi2spfinal/FAPI2SPFinalDiscoveryEndpointVerification.java
	test(
		"fapi2-security-profile-final-discovery-end-point-verification: the discovery document has what FAPI 2.0 requires (PAR, PKCE S256, the signing algorithms, private_key_jwt, iss in the response)",
		fapi2DiscoveryEndpointVerification,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalHappyFlow.java
	test(
		"fapi2-security-profile-final-happy-flow: two clients complete the PAR, DPoP-bound code flow and the resource rejects the other client's key",
		fapi2HappyFlow,
	);

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

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureMismatchedDpopJktFails.java
	if (!mtlsSenderConstrain) {
		test(
			"fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails: a dpop_jkt that does not match the PAR request's DPoP proof is rejected",
			fapi2EnsureMismatchedDpopJktFails,
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

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureDifferentNonceInsideAndOutsideRequestObject.java
	if (!plainOauth) {
		test(
			"fapi2-security-profile-final-ensure-different-nonce-inside-and-outside-request-object: a nonce outside the request object differing from the one inside is rejected with invalid_request or ignored",
			fapi2EnsureDifferentNonceInsideAndOutsideRequestObject,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureDifferentStateInsideAndOutsideRequestObject.java
	test(
		"fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object: a state outside the request object differing from the one inside is rejected with invalid_request or ignored",
		fapi2EnsureDifferentStateInsideAndOutsideRequestObject,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalStateOnlyOutsideRequestObjectNotUsed.java
	test(
		"fapi2-security-profile-final-state-only-outside-request-object-not-used: a state only outside the request object is ignored (no state, no s_hash) or the request rejected",
		fapi2StateOnlyOutsideRequestObjectNotUsed,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureRequestObjectWithoutRedirectUriFails.java
	test(
		"fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails: a request without redirect_uri is rejected at the PAR or the authorization endpoint",
		fapi2EnsureRequestObjectWithoutRedirectUriFails,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalPAREnsureServerAcceptsReusedRequestUriBeforeAuthenticationCompletion.java
	test(
		"fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds: a request_uri visited once without logging in is still accepted on the second visit",
		fapi2PAREnsureServerAcceptsReusedRequestUriBeforeAuthenticationCompletion,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalPARAttemptReuseRequestUri.java
	test(
		"fapi2-security-profile-final-par-attempt-reuse-request_uri: a request_uri already used for an authorization is rejected with invalid_request_uri (a warning when it is accepted)",
		fapi2PARAttemptReuseRequestUri,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalPARAttemptToUseExpiredRequestUri.java
	test(
		"fapi2-security-profile-final-par-attempt-to-use-expired-request_uri: a request_uri used after its expires_in is rejected with invalid_request_uri",
		fapi2PARAttemptToUseExpiredRequestUri,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalPAREnsureRequestUriIsBoundToClient.java
	test(
		"fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client: the first client's request_uri sent with the second client's client_id is rejected",
		fapi2PAREnsureRequestUriIsBoundToClient,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalPARRejectRequestUriInParAuthorizationFormParams.java
	test(
		"fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param: a PAR request with a request_uri form parameter is rejected",
		fapi2PARRejectRequestUriInParAuthorizationFormParams,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalPARRejectInvalidHttpVerb.java
	test(
		"fapi2-security-profile-final-par-attempt-invalid-http-method: a PUT to the PAR endpoint is answered with an HTTP error",
		fapi2PARRejectInvalidHttpVerb,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalPAREnsurePKCECodeVerifierRequired.java
	test(
		"fapi2-security-profile-final-ensure-pkce-code-verifier-required: a token request without code_verifier is rejected with invalid_grant",
		fapi2PAREnsurePKCECodeVerifierRequired,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalPARIncorrectPKCECodeVerifierRejected.java
	test(
		"fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected: a token request with a wrong code_verifier is rejected with invalid_grant",
		fapi2PARIncorrectPKCECodeVerifierRejected,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalPAREnsurePlainPKCERejected.java
	test(
		"fapi2-security-profile-final-par-plain-pkce-rejected: a PAR request with code_challenge_method=plain is rejected at the PAR or the authorization endpoint",
		fapi2PAREnsurePlainPKCERejected,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalUserRejectsAuthentication.java
	test(
		"fapi2-security-profile-final-user-rejects-authentication: the user rejecting the login sends access_denied to the redirect_uri, for both clients",
		fapi2UserRejectsAuthentication,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureAuthorizationRequestWith64CharNonceSuccess.java
	if (!plainOauth) {
		test(
			"fapi2-security-profile-final-ensure-authorization-request-with-64-char-nonce-success: a 64 character nonce is accepted and returned in the id_token",
			fapi2EnsureAuthorizationRequestWith64CharNonceSuccess,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalTestClaimsParameterIdentityClaims.java
	if (!plainOauth) {
		test(
			"fapi2-security-profile-final-test-claims-parameter-identity-claims: every standard claim of claims_supported requested with the claims parameter comes back in the id_token or at the userinfo endpoint",
			fapi2TestClaimsParameterIdentityClaims,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalCheckDpopProofNbfExp.java
	if (!mtlsSenderConstrain) {
		test(
			"fapi2-security-profile-final-check-dpop-proof-nbf-exp: DPoP proofs with nbf and exp are accepted at the token and resource endpoints",
			fapi2CheckDpopProofNbfExp,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureDpopProofWithIat10SecondsBeforeSucceeds.java
	if (!mtlsSenderConstrain) {
		test(
			"fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-before-succeeds: DPoP proofs with iat 10 seconds in the past are accepted at the PAR, token and resource endpoints",
			fapi2EnsureDpopProofWithIat10SecondsBeforeSucceeds,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureDpopProofWithIat10SecondsAfterSucceeds.java
	if (!mtlsSenderConstrain) {
		test(
			"fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-after-succeeds: DPoP proofs with iat 10 seconds in the future are accepted at the PAR, token and resource endpoints",
			fapi2EnsureDpopProofWithIat10SecondsAfterSucceeds,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureTokenEndpointFailsWithMismatchedDpopProofJkt.java
	if (!mtlsSenderConstrain) {
		test(
			"fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt: a token request whose DPoP proof key differs from the PAR request's is rejected",
			fapi2EnsureTokenEndpointFailsWithMismatchedDpopProofJkt,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureTokenEndpointFailsWithMismatchedDpopJkt.java
	if (!mtlsSenderConstrain) {
		test(
			"fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-jkt: a token request whose DPoP proof key does not match the dpop_jkt of the authorization request is rejected",
			fapi2EnsureTokenEndpointFailsWithMismatchedDpopJkt,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureDpopProofAtParEndpointBindingSuccess.java
	if (!mtlsSenderConstrain) {
		test(
			"fapi2-security-profile-final-ensure-dpopproof-at-par-endpoint-binding-success: the code bound to the PAR request's DPoP proof key is redeemed with the same key",
			fapi2EnsureDpopProofAtParEndpointBindingSuccess,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureDpopAuthCodeBindingSuccess.java
	if (!mtlsSenderConstrain) {
		test(
			"fapi2-security-profile-final-ensure-dpop-auth-code-binding-success: a dpop_jkt matching the DPoP proofs of the PAR and token requests succeeds",
			fapi2EnsureDpopAuthCodeBindingSuccess,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureAuthorizationRequestWithLongNonce.java
	if (!plainOauth) {
		test(
			"fapi2-security-profile-final-ensure-authorization-request-with-long-nonce: a 384 character nonce is returned intact or rejected with invalid_request",
			fapi2EnsureAuthorizationRequestWithLongNonce,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureAuthorizationRequestWithLongState.java
	test(
		"fapi2-security-profile-final-ensure-authorization-request-with-long-state: a 1000 character state is returned intact or rejected with invalid_request",
		fapi2EnsureAuthorizationRequestWithLongState,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureRegisteredRedirectUri.java
	if (!plainFapi) {
		test(
			"fapi2-security-profile-final-ensure-registered-redirect-uri: an unregistered redirect_uri is rejected at the PAR endpoint or with an error page",
			fapi2EnsureRegisteredRedirectUri,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalTolerateUnregisteredRedirectUri.java
	if (!registeredRedirectUriProfile) {
		test(
			"fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri: an unregistered redirect_uri is accepted (RFC 9126 2.4) or rejected at the PAR endpoint or with an error page",
			fapi2TolerateUnregisteredRedirectUri,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureUnsignedAuthorizationRequestWithoutUsingParFails.java
	test(
		"fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails: an authorization request with its parameters in the query (no PAR) is rejected with invalid_request or an error page",
		fapi2EnsureUnsignedAuthorizationRequestWithoutUsingParFails,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureRedirectUriInAuthorizationRequest.java
	test(
		"fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request: a request without redirect_uri is rejected at the PAR endpoint, with an error page, or the registered one is used",
		fapi2EnsureRedirectUriInAuthorizationRequest,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureResponseTypeCodeIdTokenFails.java
	test(
		"fapi2-security-profile-final-ensure-response-type-code-idtoken-fails: response_type=code id_token is rejected at the PAR or the authorization endpoint",
		fapi2EnsureResponseTypeCodeIdTokenFails,
	);

	// TODO(port): FAPI2SPFinalAustraliaConnectIdEnsureInvalidPurposeFails.java (fapi_profile=connectid_au only)

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureResponseTypeTokenFails.java
	test(
		"fapi2-security-profile-final-ensure-response-type-token-fails: response_type=token is rejected at the PAR or the authorization endpoint",
		fapi2EnsureResponseTypeTokenFails,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalAttemptToUseExpiredAuthCode.java
	test(
		"fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code: a code used for the first time after 62 seconds is rejected with invalid_grant",
		fapi2AttemptToUseExpiredAuthCode,
	);

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureSignedClientAssertionWithRS256Fails.java
	if (!notPrivateKeyJwt) {
		test(
			"fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails: a client assertion signed with RS256 is rejected with invalid_client",
			fapi2EnsureSignedClientAssertionWithRS256Fails,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureClientAssertionWithExpIs5MinutesInPastFails.java
	if (!notPrivateKeyJwt) {
		test(
			"fapi2-security-profile-final-ensure-client-assertion-with-exp-is-5-minutes-in-past-fails: a client assertion whose exp is 5 minutes in the past is rejected",
			fapi2EnsureClientAssertionWithExpIs5MinutesInPastFails,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureClientAssertionWithWrongAudFails.java
	if (!notPrivateKeyJwt) {
		test(
			"fapi2-security-profile-final-ensure-client-assertion-with-wrong-aud-fails: a client assertion with the wrong aud is rejected",
			fapi2EnsureClientAssertionWithWrongAudFails,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalEnsureClientAssertionWithNoSubFails.java
	if (!notPrivateKeyJwt) {
		test(
			"fapi2-security-profile-final-ensure-client-assertion-with-no-sub-fails: a client assertion without sub is rejected",
			fapi2EnsureClientAssertionWithNoSubFails,
		);
	}

	// upstream: fapi2spfinal/FAPI2SPFinalDpopNegativeTests.java
	if (!mtlsSenderConstrain) {
		test(
			"fapi2-security-profile-final-dpop-negative-tests: the resource rejects every invalid DPoP proof and accepts the valid ones",
			fapi2DpopNegativeTests,
		);
	}

	// TODO(port): FAPI2SPFinalCdrEnsureSharingDurationZeroGivesNoRefreshToken.java (fapi_profile=consumerdataright_au only)
	// TODO(port): FAPI2SPFinalCdrEnsureNegativeSharingDurationFails.java (fapi_profile=consumerdataright_au only)
	// TODO(port): FAPI2SPFinalCdrRefreshTokenIntrospectionExpiry.java (fapi_profile=consumerdataright_au only)
	// TODO(port): FAPI2SPFinalCdrArrangementAmendmentRevokesOldTokens.java (fapi_profile=consumerdataright_au only)
	// TODO(port): FAPI2SPFinalCdrEnsureUnrecognisedArrangementIdFails.java (fapi_profile=consumerdataright_au only)
	// TODO(port): FAPI2SPFinalBrazilEnsureBadPaymentSignatureFails.java (fapi_profile=openbanking_brazil only)
	// TODO(port): FAPI2SPFinalAustraliaConnectIdTestClaimsParameterIdTokenIdentityClaims.java (fapi_profile=connectid_au only)
	// TODO(port): FAPI2SPFinalGrantManagementQueryAndRevoke.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementMerge.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementReplace.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementEnsureInvalidGrantIdFails.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementEnsureQueryNonExistentGrantFails.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementEnsureWrongClientCannotQueryGrant.java (grant_management=enabled only)
	// TODO(port): FAPI2SPFinalGrantManagementEnsureWrongClientCannotRevokeGrant.java (grant_management=enabled only)
});

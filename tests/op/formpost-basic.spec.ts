/**
 * OpenID Connect Core: Form Post Basic Certification Profile, OP tests (upstream openid/OIDCCFormPostBasicTestPlan.java).
 *
 * The basic plan's module lists with response_mode=form_post (upstream AbstractFormPostTestPlan.changeResponseTypeToFormPost):
 * response_type=code, client_auth_type=client_secret_basic (client_secret_post for oidcc-server-client-secret-post);
 * the user selects server_metadata and client_registration. The OP posts the authorization response to the
 * redirect_uri as a form. The module bodies are in tests/op/shared.ts.
 *
 *   CONFORMANCE_PROJECT=op-formpost-basic pnpm test tests/op/formpost-basic.spec.ts
 */
import { test, variantNotApplicable } from "../fixtures.ts";
import {
	oidccAlternateHappyFlow,
	oidccClaimsEssential,
	oidccClaimsLocales,
	oidccCodeReuse,
	oidccCodeReuse30Seconds,
	oidccDisplayPage,
	oidccDisplayPopup,
	oidccEnsurePostRequestSucceeds,
	oidccEnsureRegisteredRedirectUri,
	oidccEnsureRequestObjectWithRedirectUri,
	oidccEnsureRequestWithAcrValuesSucceeds,
	oidccEnsureRequestWithUnknownParameterSucceeds,
	oidccEnsureRequestWithValidPkceSucceeds,
	oidccEnsureRequestWithoutNonceSucceedsForCodeFlow,
	oidccIdTokenHint,
	oidccIdTokenSignature,
	oidccIdTokenUnsigned,
	oidccLoginHint,
	oidccMaxAge1,
	oidccMaxAge10000,
	oidccPromptLogin,
	oidccPromptNoneLoggedIn,
	oidccPromptNoneNotLoggedIn,
	oidccRefreshToken,
	oidccRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported,
	oidccResponseTypeMissing,
	oidccScopeAddress,
	oidccScopeAll,
	oidccScopeEmail,
	oidccScopePhone,
	oidccScopeProfile,
	oidccServer,
	oidccServerClientSecretPost,
	oidccUiLocales,
	oidccUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported,
	oidccUserInfoGet,
	oidccUserInfoPostBody,
	oidccUserInfoPostHeader,
} from "./shared.ts";

test.describe("oidcc-formpost-basic-certification-test-plan", () => {
	const plan = {
		name: "oidcc-formpost-basic-certification-test-plan",
		variant: { response_type: "code", client_auth_type: "client_secret_basic", response_mode: "form_post" },
	};
	test.use({ plan });

	// upstream: openid/OIDCCServerTest.java (OP-Response-code)
	test(
		"oidcc-server: the code flow returns a valid code, tokens and id_token, and the access token works at userinfo",
		oidccServer,
	);

	// upstream: openid/OIDCCResponseTypeMissing.java (OP-Response-Missing)
	test(
		"oidcc-response-type-missing: a request without response_type is rejected with an error redirect or an error page",
		oidccResponseTypeMissing,
	);

	// upstream @VariantNotApplicable(parameter = ClientRegistration.class, values = { "static_client" }): the module
	// registers a client without an id_token signing alg, so the plan does not have it for static clients
	if (!variantNotApplicable(plan, { client_registration: ["static_client"] })) {
		// upstream: openid/OIDCCIdTokenSignature.java (OP-IDToken-Signature, OP-IDToken-kid)
		test(
			"oidcc-idtoken-signature: without a requested algorithm the id_token is signed with RS256 and names its key",
			oidccIdTokenSignature,
		);
	}

	// upstream: openid/OIDCCAuthCodeReuse.java (OP-OAuth-2nd)
	test("oidcc-codereuse: a second token request with the same code is rejected with invalid_grant", oidccCodeReuse);

	// upstream: openid/OIDCCScopeAddress.java (OP-scope-address)
	test(
		"oidcc-scope-address: scope=openid address returns the address claim at the userinfo endpoint",
		oidccScopeAddress,
	);

	// upstream: openid/OIDCCScopeAll.java (OP-scope-all)
	test(
		"oidcc-scope-all: scope=openid email phone address profile returns all the scopes' claims at the userinfo endpoint",
		oidccScopeAll,
	);

	// upstream: openid/OIDCCScopeEmail.java (OP-scope-email)
	test(
		"oidcc-scope-email: scope=openid email returns the email claims at the userinfo endpoint, not in the id_token",
		oidccScopeEmail,
	);

	// upstream: openid/OIDCCScopePhone.java (OP-scope-phone)
	test("oidcc-scope-phone: scope=openid phone returns the phone claims at the userinfo endpoint", oidccScopePhone);

	// upstream: openid/OIDCCScopeProfile.java (OP-scope-profile)
	test(
		"oidcc-scope-profile: scope=openid profile returns the profile claims at the userinfo endpoint",
		oidccScopeProfile,
	);

	// upstream: openid/OIDCCClaimsEssential.java (OP-claims-essential)
	test(
		"oidcc-claims-essential: a request for the essential name claim at userinfo succeeds and returns the name",
		oidccClaimsEssential,
	);

	// upstream: openid/OIDCCClaimsLocales.java (OP-Req-claims_locales)
	test("oidcc-claims-locales: a request with claims_locales=se does not result in an error", oidccClaimsLocales);

	// upstream: openid/OIDCCUserInfoGet.java (OP-UserInfo-Endpoint)
	test(
		"oidcc-userinfo-get: the userinfo endpoint answers a GET with the access token in the Authorization header",
		oidccUserInfoGet,
	);

	// upstream: openid/OIDCCUserInfoPostBody.java (OP-UserInfo-Body)
	test(
		"oidcc-userinfo-post-body: the userinfo endpoint answers a POST with the access token in the body, or warns that it does not support it",
		oidccUserInfoPostBody,
	);

	// upstream: openid/OIDCCUserInfoPostHeader.java (OP-UserInfo-Header)
	test(
		"oidcc-userinfo-post-header: the userinfo endpoint answers a POST with the access token in the Authorization header",
		oidccUserInfoPostHeader,
	);

	// upstream: openid/OIDCCAlternateHappyFlow.java
	test(
		"oidcc-alternate-happy-flow: reversed scope order and reversed parameter order in the request make no difference",
		oidccAlternateHappyFlow,
	);

	// upstream: openid/OIDCCDisplayPage.java (OP-display-page)
	test("oidcc-display-page: a request with display=page does not result in an error", oidccDisplayPage);

	// upstream: openid/OIDCCDisplayPopup.java (OP-display-popup)
	test("oidcc-display-popup: a request with display=popup does not result in an error", oidccDisplayPopup);

	// upstream: openid/OIDCCUiLocales.java (OP-Req-ui_locales)
	test("oidcc-ui-locales: a request with ui_locales does not result in an error", oidccUiLocales);

	// upstream: openid/OIDCCLoginHint.java (OP-Req-login_hint)
	test("oidcc-login-hint: a request with a login_hint does not result in an error", oidccLoginHint);

	// upstream: openid/OIDCCIdTokenHint.java (OP-Req-id_token_hint)
	test(
		"oidcc-id-token-hint: a second authorization with prompt=none and the first id_token as id_token_hint succeeds with the same sub",
		oidccIdTokenHint,
	);

	// upstream: openid/OIDCCPromptLogin.java (OP-prompt-login)
	test(
		"oidcc-prompt-login: a second request with prompt=login makes the OP ask the user to log in again, with a later auth_time",
		oidccPromptLogin,
	);

	// upstream: openid/OIDCCPromptNoneNotLoggedIn.java (OP-prompt-none-NotLoggedIn)
	test(
		"oidcc-prompt-none-not-logged-in: prompt=none without a session is rejected with an error that required a user interface",
		oidccPromptNoneNotLoggedIn,
	);

	// upstream: openid/OIDCCPromptNoneLoggedIn.java (OP-prompt-none-LoggedIn)
	test(
		"oidcc-prompt-none-logged-in: a second request with prompt=none succeeds without a login, with the same sub and auth_time",
		oidccPromptNoneLoggedIn,
	);

	// upstream: openid/OIDCCMaxAge1.java (OP-Req-max_age=1)
	test(
		"oidcc-max-age-1: a second request with max_age=1 after 2 seconds makes the OP ask for a login again and return a later auth_time",
		oidccMaxAge1,
	);

	// upstream: openid/OIDCCMaxAge10000.java (OP-Req-max_age=10000)
	test(
		"oidcc-max-age-10000: a second request with max_age=10000 succeeds without a login, with the same sub and auth_time",
		oidccMaxAge10000,
	);

	// upstream: openid/OIDCCEnsurePostRequestSucceeds.java
	test(
		"oidcc-ensure-post-request-succeeds: an authorization request sent as POST completes with a redirect within 30 seconds",
		oidccEnsurePostRequestSucceeds,
	);

	// upstream: openid/OIDCCEnsureRegisteredRedirectUri.java (OP-redirect_uri-NotReg)
	test(
		"oidcc-ensure-registered-redirect-uri: a redirect_uri that is not registered shows an error page and never redirects",
		oidccEnsureRegisteredRedirectUri,
	);

	// upstream: openid/OIDCCEnsureRequestWithAcrValuesSucceeds.java (OP-Req-acr_values)
	test(
		"oidcc-ensure-request-with-acr-values-succeeds: a request with acr_values succeeds, and the id_token should carry one of them",
		oidccEnsureRequestWithAcrValuesSucceeds,
	);

	// upstream: openid/OIDCCEnsureRequestWithUnknownParameterSucceeds.java (OP-Req-NotUnderstood)
	test(
		"oidcc-ensure-request-with-unknown-parameter-succeeds: a request with an unknown parameter succeeds, the parameter ignored",
		oidccEnsureRequestWithUnknownParameterSucceeds,
	);

	// upstream: openid/OIDCCEnsureRequestWithValidPkceSucceeds.java
	test(
		"oidcc-ensure-request-with-valid-pkce-succeeds: a request with a valid PKCE challenge succeeds, whether or not the OP supports PKCE",
		oidccEnsureRequestWithValidPkceSucceeds,
	);

	// upstream: openid/OIDCCEnsureRequestWithoutNonceSucceedsForCodeFlow.java (OP-nonce-NoReq-code)
	test(
		"oidcc-ensure-request-without-nonce-succeeds-for-code-flow: a code flow request without nonce returns an authorization code",
		oidccEnsureRequestWithoutNonceSucceedsForCodeFlow,
	);

	// upstream: openid/OIDCCAuthCodeReuseAfter30Seconds.java (OP-OAuth-2nd-30s)
	test(
		"oidcc-codereuse-30seconds: a second token request with the same code 30 seconds later is rejected with invalid_grant, and the access token is revoked",
		oidccCodeReuse30Seconds,
	);

	test.describe("client_auth_type=client_secret_post", () => {
		// upstream: the module runs with the client_secret_post variant and, for static clients, the `client_secret_post`
		// client of the configuration
		test.use({ plan: { ...plan, variant: { ...plan.variant, client_auth_type: "client_secret_post" } } });

		// upstream: openid/OIDCCServerTestClientSecretPost.java (OP-ClientAuth-SecretPost-Dynamic)
		test(
			"oidcc-server-client-secret-post: the code flow works with client_secret_post client authentication",
			oidccServerClientSecretPost,
		);
	});

	// upstream @VariantNotApplicable(parameter = ClientRegistration.class, values = { "static_client" }): the modules
	// register a client with id_token_signed_response_alg=none or a request_uri, so the plan does not have them for
	// static clients
	if (!variantNotApplicable(plan, { client_registration: ["static_client"] })) {
		// upstream: openid/OIDCCIdTokenUnsigned.java (OP-IDToken-none)
		test(
			"oidcc-idtoken-unsigned: an id_token requested without a signature (alg=none) is returned with alg none",
			oidccIdTokenUnsigned,
		);

		// upstream: openid/OIDCCRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported.java (OP-request_uri-Unsigned)
		test(
			"oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported: an unsigned request object by request_uri is processed or rejected with request_uri_not_supported",
			oidccRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported,
		);
	}

	// upstream: openid/OIDCCUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported.java (OP-request-Unsigned)
	test(
		"oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported: an unsigned request object by value is processed or rejected with request_not_supported",
		oidccUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported,
	);

	// upstream: openid/OIDCCEnsureRequestObjectWithRedirectUri.java
	test(
		"oidcc-ensure-request-object-with-redirect-uri: the redirect_uri in the request object takes precedence over the invalid one in the request, or an error page is shown",
		oidccEnsureRequestObjectWithRedirectUri,
	);

	// upstream: openid/OIDCCRefreshToken.java
	test(
		"oidcc-refresh-token: a refresh token gives a new access token (and id_token) and is bound to the client it was issued to",
		oidccRefreshToken,
	);
});

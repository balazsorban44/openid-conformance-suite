/**
 * OpenID Connect Core: Implicit Certification Profile, OP tests (upstream openid/OIDCCImplicitTestPlan.java).
 *
 * The plan runs its modules once for response_type=id_token and once for response_type=id_token token (the userinfo
 * modules and oidcc-response-type-missing only for the latter), with client_auth_type=client_secret_basic (which the
 * implicit flow does not use) and response_mode=default; the user selects server_metadata and client_registration.
 * The id_token (and access token) come from the URL fragment; there is no token endpoint request. The module bodies
 * are in tests/op/shared.ts.
 *
 *   CONFORMANCE_PROJECT=op-implicit pnpm test tests/op/implicit.spec.ts
 */
import { test, variantNotApplicable } from "../fixtures.ts";
import {
	oidccAlternateHappyFlow,
	oidccClaimsEssential,
	oidccClaimsLocales,
	oidccDisplayPage,
	oidccDisplayPopup,
	oidccEnsureRegisteredRedirectUri,
	oidccEnsureRequestObjectWithRedirectUri,
	oidccEnsureRequestWithAcrValuesSucceeds,
	oidccEnsureRequestWithUnknownParameterSucceeds,
	oidccEnsureRequestWithoutNonceFails,
	oidccIdTokenHint,
	oidccIdTokenSignature,
	oidccLoginHint,
	oidccMaxAge1,
	oidccMaxAge10000,
	oidccPromptLogin,
	oidccPromptNoneLoggedIn,
	oidccPromptNoneNotLoggedIn,
	oidccRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported,
	oidccResponseTypeMissing,
	oidccScopeAddress,
	oidccScopeAll,
	oidccScopeEmail,
	oidccScopePhone,
	oidccScopeProfile,
	oidccServer,
	oidccUiLocales,
	oidccUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported,
	oidccUserInfoGet,
	oidccUserInfoPostBody,
	oidccUserInfoPostHeader,
} from "./shared.ts";

const PLAN = "oidcc-implicit-certification-test-plan";

/** The variant a module list of the plan fixes (client_secret_basic is not used, upstream has to name one) */
function planOf(responseType: "id_token" | "id_token token") {
	return {
		name: PLAN,
		variant: { response_type: responseType, client_auth_type: "client_secret_basic", response_mode: "default" },
	};
}

test.describe(PLAN, () => {
	// upstream: the general list of tests, run for both response types
	for (const responseType of ["id_token", "id_token token"] as const) {
		test.describe(`response_type=${responseType}`, () => {
			const plan = planOf(responseType);
			test.use({ plan });

			// upstream: openid/OIDCCServerTest.java (OP-Response-id_token, OP-Response-id_token+token)
			test(
				"oidcc-server: the authorization endpoint returns a valid id_token (with an at_hash for its access token), and the access token works at userinfo",
				oidccServer,
			);

			// upstream @VariantNotApplicable(parameter = ClientRegistration.class, values = { "static_client" })
			if (!variantNotApplicable(plan, { client_registration: ["static_client"] })) {
				// upstream: openid/OIDCCIdTokenSignature.java (OP-IDToken-Signature, OP-IDToken-kid)
				test(
					"oidcc-idtoken-signature: without a requested algorithm the id_token is signed with RS256 and names its key",
					oidccIdTokenSignature,
				);
			}

			// upstream: openid/OIDCCEnsureRequestWithoutNonceFails.java (OP-nonce-NoReq-noncode)
			test(
				"oidcc-ensure-request-without-nonce-fails: a request without nonce is rejected with invalid_request or an error page, as the authorization endpoint returns an id_token",
				oidccEnsureRequestWithoutNonceFails,
			);

			// upstream: openid/OIDCCScopeProfile.java (OP-scope-profile)
			test(
				"oidcc-scope-profile: scope=openid profile returns the profile claims at the userinfo endpoint (in the id_token without an access token)",
				oidccScopeProfile,
			);

			// upstream: openid/OIDCCScopeEmail.java (OP-scope-email)
			test(
				"oidcc-scope-email: scope=openid email returns the email claims at the userinfo endpoint (in the id_token without an access token)",
				oidccScopeEmail,
			);

			// upstream: openid/OIDCCScopeAddress.java (OP-scope-address)
			test(
				"oidcc-scope-address: scope=openid address returns the address claim at the userinfo endpoint (in the id_token without an access token)",
				oidccScopeAddress,
			);

			// upstream: openid/OIDCCScopePhone.java (OP-scope-phone)
			test(
				"oidcc-scope-phone: scope=openid phone returns the phone claims at the userinfo endpoint (in the id_token without an access token)",
				oidccScopePhone,
			);

			// upstream: openid/OIDCCScopeAll.java (OP-scope-All)
			test(
				"oidcc-scope-all: scope=openid email phone address profile returns all the scopes' claims at the userinfo endpoint (in the id_token without an access token)",
				oidccScopeAll,
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

			// upstream: openid/OIDCCEnsureRequestWithUnknownParameterSucceeds.java (OP-Req-NotUnderstood)
			test(
				"oidcc-ensure-request-with-unknown-parameter-succeeds: a request with an unknown parameter succeeds, the parameter ignored",
				oidccEnsureRequestWithUnknownParameterSucceeds,
			);

			// upstream: openid/OIDCCIdTokenHint.java (OP-Req-id_token_hint)
			test(
				"oidcc-id-token-hint: a second authorization with prompt=none and the first id_token as id_token_hint succeeds with the same sub",
				oidccIdTokenHint,
			);

			// upstream: openid/OIDCCLoginHint.java (OP-Req-login_hint)
			test("oidcc-login-hint: a request with a login_hint does not result in an error", oidccLoginHint);

			// upstream: openid/OIDCCUiLocales.java (OP-Req-ui_locales)
			test("oidcc-ui-locales: a request with ui_locales does not result in an error", oidccUiLocales);

			// upstream: openid/OIDCCClaimsLocales.java (OP-Req-claims_locales)
			test("oidcc-claims-locales: a request with claims_locales=se does not result in an error", oidccClaimsLocales);

			// upstream: openid/OIDCCEnsureRequestWithAcrValuesSucceeds.java (OP-Req-acr_values)
			test(
				"oidcc-ensure-request-with-acr-values-succeeds: a request with acr_values succeeds, and the id_token should carry one of them",
				oidccEnsureRequestWithAcrValuesSucceeds,
			);

			// upstream: openid/OIDCCEnsureRegisteredRedirectUri.java (OP-redirect_uri-NotReg)
			test(
				"oidcc-ensure-registered-redirect-uri: a redirect_uri that is not registered shows an error page and never redirects",
				oidccEnsureRegisteredRedirectUri,
			);

			// upstream @VariantNotApplicable(parameter = ClientRegistration.class, values = { "static_client" })
			if (!variantNotApplicable(plan, { client_registration: ["static_client"] })) {
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

			// upstream: openid/OIDCCClaimsEssential.java (OP-claims-essential)
			test(
				"oidcc-claims-essential: a request for the essential name claim (in the id_token without an access token, else at userinfo) succeeds and returns the name",
				oidccClaimsEssential,
			);
		});
	}

	// upstream: the userinfo tests are not applicable to response_type=id_token (no access token); the response type
	// missing test runs once only
	test.describe("response_type=id_token token", () => {
		test.use({ plan: planOf("id_token token") });

		// upstream: openid/OIDCCUserInfoGet.java (OP-UserInfo-Endpoint)
		test(
			"oidcc-userinfo-get: the userinfo endpoint answers a GET with the access token in the Authorization header",
			oidccUserInfoGet,
		);

		// upstream: openid/OIDCCUserInfoPostHeader.java (OP-UserInfo-Header)
		test(
			"oidcc-userinfo-post-header: the userinfo endpoint answers a POST with the access token in the Authorization header",
			oidccUserInfoPostHeader,
		);

		// upstream: openid/OIDCCUserInfoPostBody.java (OP-UserInfo-Body)
		test(
			"oidcc-userinfo-post-body: the userinfo endpoint answers a POST with the access token in the body, or warns that it does not support it",
			oidccUserInfoPostBody,
		);

		// upstream: openid/OIDCCResponseTypeMissing.java (OP-Response-Missing)
		test(
			"oidcc-response-type-missing: a request without response_type is rejected with an error redirect or an error page",
			oidccResponseTypeMissing,
		);
	});
});

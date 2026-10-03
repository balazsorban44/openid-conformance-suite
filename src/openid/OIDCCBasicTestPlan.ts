import { ClientAuthType } from "../variant/ClientAuthType.ts";
import { ResponseMode } from "../variant/ResponseMode.ts";
import { ResponseType } from "../variant/ResponseType.ts";
import {
	ModuleListEntry,
	ProfileNames,
	SpecFamilyNames,
	TestPlan,
	Variant,
	type PublishTestPlan,
	type VariantSelection,
} from "../framework/index.ts";
import { OIDCCAlternateHappyFlow } from "./OIDCCAlternateHappyFlow.ts";
import { OIDCCAuthCodeReuse } from "./OIDCCAuthCodeReuse.ts";
import { OIDCCAuthCodeReuseAfter30Seconds } from "./OIDCCAuthCodeReuseAfter30Seconds.ts";
import { OIDCCClaimsEssential } from "./OIDCCClaimsEssential.ts";
import { OIDCCClaimsLocales } from "./OIDCCClaimsLocales.ts";
import { OIDCCDisplayPage } from "./OIDCCDisplayPage.ts";
import { OIDCCDisplayPopup } from "./OIDCCDisplayPopup.ts";
import { OIDCCEnsurePostRequestSucceeds } from "./OIDCCEnsurePostRequestSucceeds.ts";
import { OIDCCEnsureRegisteredRedirectUri } from "./OIDCCEnsureRegisteredRedirectUri.ts";
import { OIDCCEnsureRequestObjectWithRedirectUri } from "./OIDCCEnsureRequestObjectWithRedirectUri.ts";
import { OIDCCEnsureRequestWithAcrValuesSucceeds } from "./OIDCCEnsureRequestWithAcrValuesSucceeds.ts";
import { OIDCCEnsureRequestWithUnknownParameterSucceeds } from "./OIDCCEnsureRequestWithUnknownParameterSucceeds.ts";
import { OIDCCEnsureRequestWithValidPkceSucceeds } from "./OIDCCEnsureRequestWithValidPkceSucceeds.ts";
import { OIDCCEnsureRequestWithoutNonceSucceedsForCodeFlow } from "./OIDCCEnsureRequestWithoutNonceSucceedsForCodeFlow.ts";
import { OIDCCIdTokenHint } from "./OIDCCIdTokenHint.ts";
import { OIDCCIdTokenSignature } from "./OIDCCIdTokenSignature.ts";
import { OIDCCIdTokenUnsigned } from "./OIDCCIdTokenUnsigned.ts";
import { OIDCCLoginHint } from "./OIDCCLoginHint.ts";
import { OIDCCMaxAge1 } from "./OIDCCMaxAge1.ts";
import { OIDCCMaxAge10000 } from "./OIDCCMaxAge10000.ts";
import { OIDCCPromptLogin } from "./OIDCCPromptLogin.ts";
import { OIDCCPromptNoneLoggedIn } from "./OIDCCPromptNoneLoggedIn.ts";
import { OIDCCPromptNoneNotLoggedIn } from "./OIDCCPromptNoneNotLoggedIn.ts";
import { OIDCCRefreshToken } from "./OIDCCRefreshToken.ts";
import { OIDCCRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported } from "./OIDCCRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported.ts";
import { OIDCCResponseTypeMissing } from "./OIDCCResponseTypeMissing.ts";
import { OIDCCScopeAddress } from "./OIDCCScopeAddress.ts";
import { OIDCCScopeAll } from "./OIDCCScopeAll.ts";
import { OIDCCScopeEmail } from "./OIDCCScopeEmail.ts";
import { OIDCCScopePhone } from "./OIDCCScopePhone.ts";
import { OIDCCScopeProfile } from "./OIDCCScopeProfile.ts";
import { OIDCCServerTest } from "./OIDCCServerTest.ts";
import { OIDCCServerTestClientSecretPost } from "./OIDCCServerTestClientSecretPost.ts";
import { OIDCCUiLocales } from "./OIDCCUiLocales.ts";
import { OIDCCUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported } from "./OIDCCUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported.ts";
import { OIDCCUserInfoGet } from "./OIDCCUserInfoGet.ts";
import { OIDCCUserInfoPostBody } from "./OIDCCUserInfoPostBody.ts";
import { OIDCCUserInfoPostHeader } from "./OIDCCUserInfoPostHeader.ts";

export class OIDCCBasicTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-basic-certification-test-plan",
		displayName: "OpenID Connect Core: Basic Certification Profile Authorization server test",
		profile: ProfileNames.optest,
		specFamily: SpecFamilyNames.oidcc,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		// ClientRegistration.class is not specified so will be offered in the menu
		// This plan attempts to match 'basic' as defined here:
		// https://openid.net/wordpress-content/uploads/2018/06/OpenID-Connect-Conformance-Profiles.pdf
		// the tests are in the same order as the table and the comments list the 3rd column in the table.
		const variantCodeBasic = [
			new Variant(ResponseType, "code"),
			// the choice of client_secret_basic here is relatively arbitary, and client_secret_post could have been
			// used instead - the certification profile requires that both basic and post are tested, but doesn't
			// dictate which variant the other tests are run with
			new Variant(ClientAuthType, "client_secret_basic"),
			new Variant(ResponseMode, "default"),
		];

		return [
			new ModuleListEntry(
				[
					OIDCCServerTest, // OP-Response-code
					OIDCCResponseTypeMissing, // OP-Response-Missing
					// 4 x IdToken.verify() are covered by OIDCCServerTest
					OIDCCIdTokenSignature, // OP-IDToken-Signature & OP-IDToken-kid
					OIDCCIdTokenUnsigned, // OP-IDToken-none
					OIDCCUserInfoGet, // OP-UserInfo-Endpoint
					OIDCCUserInfoPostHeader, // OP-UserInfo-Header
					OIDCCUserInfoPostBody, // OP-UserInfo-Body
					// OpenIDSchema.verify() covered by OP-UserInfo-Endpoint
					OIDCCEnsureRequestWithoutNonceSucceedsForCodeFlow, // OP-nonce-NoReq-code
					// OP-nonce-code covered by OIDCCServerTest
					// OP-IDToken-Signature here is a duplicate covered above
					OIDCCScopeProfile, // OP-scope-profile
					OIDCCScopeEmail, // OP-scope-email
					OIDCCScopeAddress, // OP-scope-address
					OIDCCScopePhone, // OP-scope-phone
					OIDCCScopeAll, // OP-scope-All
					OIDCCAlternateHappyFlow, // new test in java suite
					OIDCCDisplayPage, // OP-display-page
					OIDCCDisplayPopup, // OP-display-popup
					OIDCCPromptLogin, // OP-prompt-login
					OIDCCPromptNoneNotLoggedIn, // OP-prompt-none-NotLoggedIn
					OIDCCPromptNoneLoggedIn, // OP-prompt-none-LoggedIn
					OIDCCMaxAge1, // 3 x OP-Req-max_age=1
					OIDCCMaxAge10000, // OP-Req-max_age=10000
					OIDCCEnsureRequestWithUnknownParameterSucceeds, // OP-Req-NotUnderstood
					OIDCCIdTokenHint, // OP-Req-id_token_hint
					OIDCCLoginHint, // OP-Req-login_hint
					OIDCCUiLocales, // OP-Req-ui_locales
					OIDCCClaimsLocales, // OP-Req-claims_locales
					OIDCCEnsureRequestWithAcrValuesSucceeds, // OP-Req-acr_values
					// VerifyState() covered by OIDCCServerTest
					OIDCCAuthCodeReuse, // OP-OAuth-2nd
					OIDCCAuthCodeReuseAfter30Seconds, // OP-OAuth-2nd-30s
					// OP-OAuth-2nd-Revokes covered by oidcc-codereuse-30seconds
					// OP-OAuth-2nd-30s is already covered
					OIDCCEnsureRegisteredRedirectUri, // OP-redirect_uri-NotReg
					// OP-ClientAuth-Basic-Dynamic covered by OIDCServerTest
					// OP-ClientAuth-Basic-Static covered by OIDCServerTest
					OIDCCEnsurePostRequestSucceeds,
				],
				variantCodeBasic,
			),
			// now switch variants to check that client_secret_post works
			new ModuleListEntry(
				[OIDCCServerTestClientSecretPost], // OP-ClientAuth-SecretPost-Dynamic
				[
					new Variant(ResponseType, "code"),
					new Variant(ClientAuthType, "client_secret_post"),
					new Variant(ResponseMode, "default"),
				],
			),
			// remaining variants run with original variants
			// OP-ClientAuth-SecretPost-Static same as OP-ClientAuth-SecretPost-Dynamic
			new ModuleListEntry(
				[
					OIDCCRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported, // OP-request_uri-Unsigned
					OIDCCUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported, // OP-request-Unsigned
					OIDCCClaimsEssential, // OP-claims-essential
					OIDCCEnsureRequestObjectWithRedirectUri, // new test that ensures OP is processing the request object when passing OIDCCUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported
					OIDCCRefreshToken, // new test; skipped if refresh tokens not supported
					OIDCCEnsureRequestWithValidPkceSucceeds, // new test
				],
				variantCodeBasic,
			),
		];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["Basic OP"];
	}
}

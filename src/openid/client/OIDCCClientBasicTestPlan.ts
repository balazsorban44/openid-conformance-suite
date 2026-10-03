import {
	ModuleListEntry,
	ProfileNames,
	SpecFamilyNames,
	TestPlan,
	Variant,
	type PublishTestPlan,
	type VariantSelection,
} from "../../framework/index.ts";
import { OIDCCClientAuthType } from "../../variant/OIDCCClientAuthType.ts";
import { ResponseMode } from "../../variant/ResponseMode.ts";
import { ResponseType } from "../../variant/ResponseType.ts";
import { OIDCCClientTest } from "./OIDCCClientTest.ts";
import { OIDCCClientTestClientSecretBasic } from "./OIDCCClientTestClientSecretBasic.ts";
import { OIDCCClientTestIdTokenSigAlgNone } from "./OIDCCClientTestIdTokenSigAlgNone.ts";
import { OIDCCClientTestIdTokenSignedUsingRS256 } from "./OIDCCClientTestIdTokenSignedUsingRS256.ts";
import { OIDCCClientTestInvalidAudInIdToken } from "./OIDCCClientTestInvalidAudInIdToken.ts";
import { OIDCCClientTestInvalidIdTokenSignatureWithRS256 } from "./OIDCCClientTestInvalidIdTokenSignatureWithRS256.ts";
import { OIDCCClientTestInvalidIssuerInIdToken } from "./OIDCCClientTestInvalidIssuerInIdToken.ts";
import { OIDCCClientTestInvalidSubInUserinfoResponse } from "./OIDCCClientTestInvalidSubInUserinfoResponse.ts";
import { OIDCCClientTestKidAbsentMultipleMatchingKeysInJwks } from "./OIDCCClientTestKidAbsentMultipleMatchingKeysInJwks.ts";
import { OIDCCClientTestKidAbsentSingleJwks } from "./OIDCCClientTestKidAbsentSingleJwks.ts";
import { OIDCCClientTestMissingIatInIdToken } from "./OIDCCClientTestMissingIatInIdToken.ts";
import { OIDCCClientTestMissingSubInIdToken } from "./OIDCCClientTestMissingSubInIdToken.ts";
import { OIDCCClientTestNonceInvalid } from "./OIDCCClientTestNonceInvalid.ts";
import { OIDCCClientTestScopeUserInfoClaims } from "./OIDCCClientTestScopeUserInfoClaims.ts";

export class OIDCCClientBasicTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-client-basic-certification-test-plan",
		displayName: "OpenID Connect Core: Basic Certification Profile Relying Party Tests",
		profile: ProfileNames.rptest,
		specFamily: SpecFamilyNames.oidcc,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		// This plan attempts to match basic relying party tests as defined here:
		// https://openid.net/wordpress-content/uploads/2018/06/OpenID-Connect-Conformance-Profiles.pdf
		// the tests are in the same order as the table

		const variantResponseTypeCode = [
			new Variant(ResponseType, "code"),
			new Variant(ResponseMode, "default"),
			//Not setting a fixed client authentication variant would also work,
			//because python tests don't care which client authentication method you use
			//and OIDCCClientTestClientSecretBasic always uses client_secret_basic regardless of the selected
			//client authentication variant
			new Variant(OIDCCClientAuthType, "client_secret_basic"),
		];
		return [
			new ModuleListEntry(
				[
					OIDCCClientTest, // rp-response_type-code
					OIDCCClientTestInvalidIssuerInIdToken, //rp-id_token-issuer-mismatch
					OIDCCClientTestMissingSubInIdToken, //rp-id_token-sub
					OIDCCClientTestInvalidAudInIdToken, //rp-id_token-aud
					OIDCCClientTestMissingIatInIdToken, //rp-id_token-iat
					//TODO rp-id_token-kid-absent-single-jwks is optional in the profile document but mandatory at
					// https://rp.certification.openid.net:8080/list?profile=C
					OIDCCClientTestKidAbsentSingleJwks, //rp-id_token-kid-absent-single-jwks
					//TODO rp-id_token-kid-absent-multiple-jwks is optional in the profile document but mandatory at
					// https://rp.certification.openid.net:8080/list?profile=C
					OIDCCClientTestKidAbsentMultipleMatchingKeysInJwks, //rp-id_token-kid-absent-multiple-jwks
					OIDCCClientTestIdTokenSignedUsingRS256, //rp-id_token-sig-rs256
					OIDCCClientTestIdTokenSigAlgNone, //rp-id_token-sig-none
					//TODO rp-id_token-bad-sig-rs256 is optional in the profile document but mandatory at
					// https://rp.certification.openid.net:8080/list?profile=C
					OIDCCClientTestInvalidIdTokenSignatureWithRS256, //rp-id_token-bad-sig-rs256

					//TODO in the profile document rp-userinfo-bearer-body is listed
					// as an alternative to rp-userinfo-bearer-header but
					// since we don't have an "either TestA or TestB must pass" mechanism in the framework
					// we should just say that rp-response_type-code covers these
					//OIDCCClientTestUserinfoBearerHeader.class,	//rp-userinfo-bearer-header
					//OIDCCClientTestUserinfoBearerBody.class,	//rp-userinfo-bearer-header

					//Page 15 row 1:
					//	Does not access UserInfo Endpoint with query parameter method
					//	Does not send Access Token as URI query parameter
					//	(implicitly tested)
					//tested implicitly by OIDCCExtractBearerAccessTokenFromRequest

					OIDCCClientTestInvalidSubInUserinfoResponse, //rp-userinfo-bad-sub-claim
					OIDCCClientTestNonceInvalid, //rp-nonce-invalid

					//Profile document page 15:
					//	Scope openid present in all requests
					//	'openid' scope value should be present in the Authentication Request
					//	(implicitly tested)
					//tested implicitly by EnsureOpenIDInScopeRequest

					//TODO rp-scope-userinfo-claims is optional in the profile document but mandatory at
					// https://rp.certification.openid.net:8080/list?profile=C
					OIDCCClientTestScopeUserInfoClaims, //rp-scope-userinfo-claims

					//OIDCCClientTestClientSecretBasic overrides client authentication variant and always uses client_secret_basic
					OIDCCClientTestClientSecretBasic, //rp-token_endpoint-client_secret_basic

					//TODO (clarify) this is enforced by EnsureValidRedirectUriForAuthorizationEndpointRequest for redirect_uri.
					// should it be enforced for something other than the redirect_uri (e.g jwks_uri)?
					//Uses https for all endpoints unless only using code flow
					//Uses HTTPS for all endpoints
					//(implicitly tested)
				],
				variantResponseTypeCode,
			),
		];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["Basic RP"];
	}
}

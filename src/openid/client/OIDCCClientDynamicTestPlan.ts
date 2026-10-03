import {
	ModuleListEntry,
	ProfileNames,
	SpecFamilyNames,
	TestPlan,
	Variant,
	type PublishTestPlan,
	type VariantSelection,
} from "../../framework/index.ts";
import { ClientRegistration } from "../../variant/ClientRegistration.ts";
import { ClientRequestType } from "../../variant/ClientRequestType.ts";
import { ResponseType } from "../../variant/ResponseType.ts";
import { OIDCCClientTestDiscoveryIssuerMismatch } from "./config/OIDCCClientTestDiscoveryIssuerMismatch.ts";
import { OIDCCClientTestDiscoveryJwksUriKeys } from "./config/OIDCCClientTestDiscoveryJwksUriKeys.ts";
import { OIDCCClientTestDiscoveryOpenIDConfiguration } from "./config/OIDCCClientTestDiscoveryOpenIDConfiguration.ts";
import { OIDCCClientTestDiscoveryWebfingerAcct } from "./config/OIDCCClientTestDiscoveryWebfingerAcct.ts";
import { OIDCCClientTestDiscoveryWebfingerURL } from "./config/OIDCCClientTestDiscoveryWebfingerURL.ts";
import { OIDCCClientTestDynamicRegistration } from "./config/OIDCCClientTestDynamicRegistration.ts";
import { OIDCCClientTestSigningKeyRotation } from "./config/OIDCCClientTestSigningKeyRotation.ts";
import { OIDCCClientTestSigningKeyRotationJustBeforeSigning } from "./config/OIDCCClientTestSigningKeyRotationJustBeforeSigning.ts";
import { OIDCCClientTestIdTokenSigAlgNone } from "./OIDCCClientTestIdTokenSigAlgNone.ts";
import { OIDCCClientTestRequestUriSignedWithNone } from "./OIDCCClientTestRequestUriSignedWithNone.ts";
import { OIDCCClientTestRequestUriSignedWithRS256 } from "./OIDCCClientTestRequestUriSignedWithRS256.ts";
import { OIDCCClientTestSignedUserinfo } from "./OIDCCClientTestSignedUserinfo.ts";

export class OIDCCClientDynamicTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-client-dynamic-certification-test-plan",
		displayName: "OpenID Connect Core: Dynamic Certification Profile Relying Party Tests",
		summary:
			"This plan requires response_type 'code', request_uri support and dynamic client registration for all tests",
		profile: ProfileNames.rptest,
		specFamily: SpecFamilyNames.oidcc,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		// This plan attempts to match dynamic relying party tests as defined here:
		// https://openid.net/wordpress-content/uploads/2018/06/OpenID-Connect-Conformance-Profiles.pdf
		// the tests are in the same order as https://rp.certification.openid.net:8080/list?profile=DYN

		const variantResponseTypeCode = [
			//same as python suite
			new Variant(ResponseType, "code"),
			//because dynamic client registration support is required
			new Variant(ClientRegistration, "dynamic_client"),
			//because request_uri support is required for two tests
			new Variant(ClientRequestType, "request_uri"),
		];
		return [
			new ModuleListEntry(
				[
					OIDCCClientTestDiscoveryWebfingerAcct, //rp-discovery-webfinger-acct
					OIDCCClientTestDiscoveryWebfingerURL, //rp-discovery-webfinger-url
					OIDCCClientTestDiscoveryOpenIDConfiguration, // rp-discovery-openid-configuration
					OIDCCClientTestDiscoveryJwksUriKeys, //rp-discovery-jwks_uri-keys
					OIDCCClientTestDiscoveryIssuerMismatch, //rp-discovery-issuer-not-matching-config
					OIDCCClientTestDynamicRegistration, //rp-registration-dynamic
					OIDCCClientTestRequestUriSignedWithRS256, //rp-request_uri-sig
					OIDCCClientTestRequestUriSignedWithNone, //rp-request_uri-unsigned
					OIDCCClientTestIdTokenSigAlgNone, //rp-id_token-sig-none

					//rp-key-rotation-op-sign-key-native does not exist in the profile document
					OIDCCClientTestSigningKeyRotationJustBeforeSigning, //rp-key-rotation-op-sign-key-native
					OIDCCClientTestSigningKeyRotation, //rp-key-rotation-op-sign-key

					OIDCCClientTestSignedUserinfo, //rp-userinfo-sig
				],
				variantResponseTypeCode,
			),
		];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["Dynamic RP"];
	}
}

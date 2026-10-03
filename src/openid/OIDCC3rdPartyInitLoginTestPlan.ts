import { ClientAuthType } from "../variant/ClientAuthType.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ResponseMode } from "../variant/ResponseMode.ts";
import { ServerMetadata } from "../variant/ServerMetadata.ts";
import {
	ModuleListEntry,
	ProfileNames,
	SpecFamilyNames,
	TestPlan,
	Variant,
	type PublishTestPlan,
	type VariantSelection,
} from "../framework/index.ts";
import { OIDCC3rdPartyInitLogin } from "./OIDCC3rdPartyInitLogin.ts";
import { OIDCC3rdPartyInitLoginNonHttps } from "./OIDCC3rdPartyInitLoginNonHttps.ts";

export class OIDCC3rdPartyInitLoginTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-3rdparty-init-login-certification-test-plan",
		displayName: "OpenID Connect Core: 3rd party initiated login Certification Profile Authorization server test",
		profile: ProfileNames.optest,
		specFamily: SpecFamilyNames.oidcc,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		// This plan attempts to match 'Third Party-Initiated Login OP Profile' as defined here:
		// https://openid.net/certification/testing/
		const variantCodeBasic = [
			new Variant(ServerMetadata, "discovery"),
			new Variant(ClientRegistration, "dynamic_client"),
			// the choice of client_secret_basic here is relatively arbitary, and client_secret_post could have been
			// used instead - the certification profile requires that both basic and post are tested, but doesn't
			// dictate which variant the other tests are run with
			new Variant(ClientAuthType, "client_secret_basic"),
			new Variant(ResponseMode, "default"),
		];

		return [
			new ModuleListEntry(
				[
					OIDCC3rdPartyInitLogin, // OP-3rd_party-init-login
					OIDCC3rdPartyInitLoginNonHttps, // OP-3rd_party-init-login-nohttps
				],
				variantCodeBasic,
			),
		];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["3rd Party-Init OP"];
	}
}

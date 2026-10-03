import {
	ModuleListEntry,
	ProfileNames,
	SpecFamilyNames,
	TestPlan,
	Variant,
	type PublishTestPlan,
	type VariantSelection,
} from "../../../../framework/index.ts";
import { ResponseType } from "../../../../variant/ResponseType.ts";
import { OIDCCClientTestRPInitLogout } from "../OIDCCClientTestRPInitLogout.ts";
import { OIDCCClientTestRPInitLogoutInvalidState } from "../OIDCCClientTestRPInitLogoutInvalidState.ts";
import { OIDCCClientTestRPInitLogoutNoState } from "../OIDCCClientTestRPInitLogoutNoState.ts";

export class OIDCCClientRPInitiatedLogoutRPBasicTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-client-rp-initiated-logout-rp-basic",
		displayName: "OpenID Connect Core: RP Initiated Logout RP Certification Profile Relying Party Tests (Basic)",
		profile: ProfileNames.rplogouttest,
		specFamily: SpecFamilyNames.oidccLogout,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		const variantResponseTypeCode = [new Variant(ResponseType, "code")];

		return [
			new ModuleListEntry(
				[OIDCCClientTestRPInitLogout, OIDCCClientTestRPInitLogoutInvalidState, OIDCCClientTestRPInitLogoutNoState],
				variantResponseTypeCode,
			),
		];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["RP-Initiated RP"];
	}
}

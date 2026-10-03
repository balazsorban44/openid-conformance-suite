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
import { OIDCCClientTestSessionManagement } from "../OIDCCClientTestSessionManagement.ts";

export class OIDCCClientSessionManagementRPBasicTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-client-rp-session-management-rp-basic",
		displayName: "OpenID Connect Core: Session Management RP Certification Profile Relying Party Tests (Basic)",
		profile: ProfileNames.rplogouttest,
		specFamily: SpecFamilyNames.oidccSessionManagement,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		const variantResponseTypeCode = [new Variant(ResponseType, "code")];

		return [new ModuleListEntry([OIDCCClientTestSessionManagement], variantResponseTypeCode)];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["Session RP"];
	}
}

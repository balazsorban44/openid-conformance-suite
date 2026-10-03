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
import { OIDCCClientTestFrontChannelLogoutRPInitiated } from "../OIDCCClientTestFrontChannelLogoutRPInitiated.ts";

export class OIDCCClientFrontChannelLogoutRPBasicTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-client-front-channel-logout-rp-basic",
		displayName: "OpenID Connect Core: Front Channel Logout RP Certification Profile Relying Party Tests (Basic)",
		profile: ProfileNames.rplogouttest,
		specFamily: SpecFamilyNames.oidccLogout,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		const variantResponseTypeCode = [new Variant(ResponseType, "code")];

		return [new ModuleListEntry([OIDCCClientTestFrontChannelLogoutRPInitiated], variantResponseTypeCode)];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["Front-Channel RP"];
	}
}

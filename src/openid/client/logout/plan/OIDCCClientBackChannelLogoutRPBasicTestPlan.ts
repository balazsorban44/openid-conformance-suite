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
import { OIDCCClientTestBackChannelLogout } from "../OIDCCClientTestBackChannelLogout.ts";
import { OIDCCClientTestBackChannelLogoutAlgNone } from "../OIDCCClientTestBackChannelLogoutAlgNone.ts";
import { OIDCCClientTestBackChannelLogoutNoEvent } from "../OIDCCClientTestBackChannelLogoutNoEvent.ts";
import { OIDCCClientTestBackChannelLogoutWithNonce } from "../OIDCCClientTestBackChannelLogoutWithNonce.ts";
import { OIDCCClientTestBackChannelLogoutWrongAlg } from "../OIDCCClientTestBackChannelLogoutWrongAlg.ts";
import { OIDCCClientTestBackChannelLogoutWrongAud } from "../OIDCCClientTestBackChannelLogoutWrongAud.ts";
import { OIDCCClientTestBackChannelLogoutWrongEvent } from "../OIDCCClientTestBackChannelLogoutWrongEvent.ts";
import { OIDCCClientTestBackChannelLogoutWrongIssuer } from "../OIDCCClientTestBackChannelLogoutWrongIssuer.ts";

export class OIDCCClientBackChannelLogoutRPBasicTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-client-back-channel-logout-rp-basic",
		displayName: "OpenID Connect Core: Back Channel Logout RP Certification Profile Relying Party Tests (Basic)",
		profile: ProfileNames.rplogouttest,
		specFamily: SpecFamilyNames.oidccLogout,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		const variantResponseTypeCode = [new Variant(ResponseType, "code")];

		return [
			new ModuleListEntry(
				[
					OIDCCClientTestBackChannelLogout,
					OIDCCClientTestBackChannelLogoutAlgNone,
					OIDCCClientTestBackChannelLogoutNoEvent,
					OIDCCClientTestBackChannelLogoutWithNonce,
					OIDCCClientTestBackChannelLogoutWrongAlg,
					OIDCCClientTestBackChannelLogoutWrongAud,
					OIDCCClientTestBackChannelLogoutWrongEvent,
					OIDCCClientTestBackChannelLogoutWrongIssuer,
				],
				variantResponseTypeCode,
			),
		];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["Back-Channel RP"];
	}
}

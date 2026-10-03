import { ClientAuthType } from "../variant/ClientAuthType.ts";
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
import { OIDCCBackChannelRpInitiatedLogout } from "./OIDCCBackChannelRpInitiatedLogout.ts";
import { OIDCCBackchannelLogoutDiscoveryEndpointVerification } from "./OIDCCBackchannelLogoutDiscoveryEndpointVerification.ts";

export class OIDCCBackchannelRpInitiatedLogoutTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-backchannel-rp-initiated-logout-certification-test-plan",
		displayName: "OpenID Connect Core: Backchannel Rp Initiated Logout Certification Profile Authorization server test",
		profile: ProfileNames.optest,
		specFamily: SpecFamilyNames.oidccLogout,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		// This plan attempts to match 'Back-Channel Logout OP' as defined here:
		// https://openid.net/certification/logout_op_testing/
		return [
			new ModuleListEntry(
				[OIDCCBackchannelLogoutDiscoveryEndpointVerification],
				[new Variant(ServerMetadata, "discovery")],
			),
			new ModuleListEntry(
				[OIDCCBackChannelRpInitiatedLogout],
				[
					new Variant(ServerMetadata, "discovery"),
					new Variant(ClientAuthType, "client_secret_basic"),
					new Variant(ResponseMode, "default"),
				],
			),
		];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["Back-Channel OP"];
	}
}

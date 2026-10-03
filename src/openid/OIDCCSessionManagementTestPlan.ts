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
import { OIDCCSessionManagementDiscoveryEndpointVerification } from "./OIDCCSessionManagementDiscoveryEndpointVerification.ts";
import { OIDCCSessionManagementRpInitiatedLogout } from "./OIDCCSessionManagementRpInitiatedLogout.ts";

export class OIDCCSessionManagementTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-session-management-certification-test-plan",
		displayName: "OpenID Connect Core: Session Management Certification Profile Authorization server test",
		profile: ProfileNames.optest,
		specFamily: SpecFamilyNames.oidccSessionManagement,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		// This plan attempts to match 'Session Management OP' as defined here:
		// https://openid.net/certification/logout_op_testing/
		return [
			new ModuleListEntry(
				[OIDCCSessionManagementDiscoveryEndpointVerification],
				[new Variant(ServerMetadata, "discovery")],
			),
			new ModuleListEntry(
				[OIDCCSessionManagementRpInitiatedLogout],
				[
					new Variant(ServerMetadata, "discovery"),
					new Variant(ClientAuthType, "client_secret_basic"),
					new Variant(ResponseMode, "default"),
				],
			),
		];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["Session OP"];
	}
}

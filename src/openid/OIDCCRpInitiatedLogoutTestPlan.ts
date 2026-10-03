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
import { OIDCCRpInitiatedLogout } from "./OIDCCRpInitiatedLogout.ts";
import { OIDCCRpInitiatedLogoutBadIdTokenHint } from "./OIDCCRpInitiatedLogoutBadIdTokenHint.ts";
import { OIDCCRpInitiatedLogoutBadLogoutRedirectUri } from "./OIDCCRpInitiatedLogoutBadLogoutRedirectUri.ts";
import { OIDCCRpInitiatedLogoutDiscoveryEndpointVerification } from "./OIDCCRpInitiatedLogoutDiscoveryEndpointVerification.ts";
import { OIDCCRpInitiatedLogoutModifiedIdTokenHint } from "./OIDCCRpInitiatedLogoutModifiedIdTokenHint.ts";
import { OIDCCRpInitiatedLogoutNoIdTokenHint } from "./OIDCCRpInitiatedLogoutNoIdTokenHint.ts";
import { OIDCCRpInitiatedLogoutNoParams } from "./OIDCCRpInitiatedLogoutNoParams.ts";
import { OIDCCRpInitiatedLogoutNoPostLogoutRedirectUri } from "./OIDCCRpInitiatedLogoutNoPostLogoutRedirectUri.ts";
import { OIDCCRpInitiatedLogoutNoState } from "./OIDCCRpInitiatedLogoutNoState.ts";
import { OIDCCRpInitiatedLogoutOnlyState } from "./OIDCCRpInitiatedLogoutOnlyState.ts";
import { OIDCCRpInitiatedLogoutQueryAddedToLogoutRedirectUri } from "./OIDCCRpInitiatedLogoutQueryAddedToLogoutRedirectUri.ts";

export class OIDCCRpInitiatedLogoutTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-rp-initiated-logout-certification-test-plan",
		displayName: "OpenID Connect Core: Rp Initiated Logout Certification Profile Authorization server test",
		profile: ProfileNames.optest,
		specFamily: SpecFamilyNames.oidccLogout,
	};

	override testModulesWithVariants(): ModuleListEntry[] {
		// This plan attempts to match 'RP-Initiated Logout OP' as defined here:
		// https://openid.net/certification/logout_op_testing/
		return [
			new ModuleListEntry(
				[OIDCCRpInitiatedLogoutDiscoveryEndpointVerification],
				[new Variant(ServerMetadata, "discovery")],
			),
			new ModuleListEntry(
				[
					OIDCCRpInitiatedLogout,
					OIDCCRpInitiatedLogoutBadLogoutRedirectUri,
					OIDCCRpInitiatedLogoutModifiedIdTokenHint,
					OIDCCRpInitiatedLogoutNoIdTokenHint,
					OIDCCRpInitiatedLogoutNoParams,
					OIDCCRpInitiatedLogoutNoPostLogoutRedirectUri,
					OIDCCRpInitiatedLogoutNoState,
					OIDCCRpInitiatedLogoutOnlyState,
					OIDCCRpInitiatedLogoutQueryAddedToLogoutRedirectUri,
					OIDCCRpInitiatedLogoutBadIdTokenHint,
				],
				[
					new Variant(ServerMetadata, "discovery"),
					new Variant(ClientAuthType, "client_secret_basic"),
					new Variant(ResponseMode, "default"),
				],
			),
		];
	}

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["RP-Initiated OP"];
	}
}

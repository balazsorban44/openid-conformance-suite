import { ProfileNames, SpecFamilyNames, TestPlan, type PublishTestPlan } from "../../../../framework/index.ts";
import { OIDCCClientTestSessionManagement } from "../OIDCCClientTestSessionManagement.ts";
import { OIDCCClientTestRPInitLogout } from "../OIDCCClientTestRPInitLogout.ts";
import { OIDCCClientTestRPInitLogoutInvalidState } from "../OIDCCClientTestRPInitLogoutInvalidState.ts";
import { OIDCCClientTestRPInitLogoutNoState } from "../OIDCCClientTestRPInitLogoutNoState.ts";
import { OIDCCClientTestFrontChannelLogoutRPInitiated } from "../OIDCCClientTestFrontChannelLogoutRPInitiated.ts";
import { OIDCCClientTestFrontChannelLogoutOPInitiated } from "../OIDCCClientTestFrontChannelLogoutOPInitiated.ts";
import { OIDCCClientTestBackChannelLogout } from "../OIDCCClientTestBackChannelLogout.ts";
import { OIDCCClientTestBackChannelLogoutAlgNone } from "../OIDCCClientTestBackChannelLogoutAlgNone.ts";
import { OIDCCClientTestBackChannelLogoutNoEvent } from "../OIDCCClientTestBackChannelLogoutNoEvent.ts";
import { OIDCCClientTestBackChannelLogoutWithNonce } from "../OIDCCClientTestBackChannelLogoutWithNonce.ts";
import { OIDCCClientTestBackChannelLogoutWrongAlg } from "../OIDCCClientTestBackChannelLogoutWrongAlg.ts";
import { OIDCCClientTestBackChannelLogoutWrongAud } from "../OIDCCClientTestBackChannelLogoutWrongAud.ts";
import { OIDCCClientTestBackChannelLogoutWrongEvent } from "../OIDCCClientTestBackChannelLogoutWrongEvent.ts";
import { OIDCCClientTestBackChannelLogoutWrongIssuer } from "../OIDCCClientTestBackChannelLogoutWrongIssuer.ts";

export class OIDCCClientLogoutTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-client-logout-test-plan",
		displayName:
			"OpenID Connect Core Client Logout Tests: Comprehensive relying party logout test (not part of certification program)",
		profile: ProfileNames.rplogouttest,
		specFamily: SpecFamilyNames.oidccLogout,
		testModules: [
			OIDCCClientTestSessionManagement,
			OIDCCClientTestRPInitLogout,
			OIDCCClientTestRPInitLogoutInvalidState,
			OIDCCClientTestRPInitLogoutNoState,
			OIDCCClientTestFrontChannelLogoutRPInitiated,
			OIDCCClientTestFrontChannelLogoutOPInitiated,
			OIDCCClientTestBackChannelLogout,
			OIDCCClientTestBackChannelLogoutAlgNone,
			OIDCCClientTestBackChannelLogoutNoEvent,
			OIDCCClientTestBackChannelLogoutWithNonce,
			OIDCCClientTestBackChannelLogoutWrongAlg,
			OIDCCClientTestBackChannelLogoutWrongAud,
			OIDCCClientTestBackChannelLogoutWrongEvent,
			OIDCCClientTestBackChannelLogoutWrongIssuer,
		],
	};
}

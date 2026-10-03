import type { PublishTestModule } from "../../../framework/index.ts";
import { AddInvalidStateToPostLogoutRedirectUriParams } from "../../../condition/as/logout/AddInvalidStateToPostLogoutRedirectUriParams.ts";
import { EnsureEndSessionEndpointRequestContainsStateParameter } from "../../../condition/as/logout/EnsureEndSessionEndpointRequestContainsStateParameter.ts";
import { OIDCCClientTestRPInitLogout } from "./OIDCCClientTestRPInitLogout.ts";

export class OIDCCClientTestRPInitLogoutInvalidState extends OIDCCClientTestRPInitLogout {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-rp-init-logout-other-state",
		displayName:
			"OIDCC: Relying party test, RP initiated logout. " +
			" The OP does return random 'state' query parameter when redirecting the User Agent back to the RP. ",
		summary:
			"The client is expected to make an authorization request " +
			"(also a token request and a optionally a userinfo request when applicable)," +
			" then terminate the session by calling the end_session_endpoint (RP-Initiated Logout) with a state parameter," +
			" at this point the conformance suite will " +
			" send a back channel logout request to the RP if only backchannel_logout_uri is set" +
			" or will send a front channel logout request to the RP if only frontchannel_logout_uri is set" +
			" or will send both front and back channel logout requests" +
			" if both backchannel_logout_uri and frontchannel_logout_uri are set," +
			" then the RP is expected to handle post logout URI redirect despite it being called with a different state parameter." +
			" Corresponds to rp-init-logout-other-state in the old test suite. " +
			"If the client does not send a state parameter, the test is skipped.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async validateEndSessionEndpointParameters(): Promise<void> {
		await super.validateEndSessionEndpointParameters();
		this.skipTestIfStateIsOmitted();
		await this.callAndStopOnFailure(EnsureEndSessionEndpointRequestContainsStateParameter);
	}

	protected override async customizeEndSessionEndpointResponseParameters(): Promise<void> {
		await this.callAndStopOnFailure(AddInvalidStateToPostLogoutRedirectUriParams, "OIDCRIL-2");
	}
}

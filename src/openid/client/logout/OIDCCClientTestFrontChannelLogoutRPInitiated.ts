import type { PublishTestModule } from "../../../framework/index.ts";
import { AbstractOIDCCClientFrontChannelLogoutTest } from "./AbstractOIDCCClientFrontChannelLogoutTest.ts";

export class OIDCCClientTestFrontChannelLogoutRPInitiated extends AbstractOIDCCClientFrontChannelLogoutTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-rp-frontchannel-rpinitlogout",
		displayName: "OIDCC: Relying party test, RP initiated front channel logout.",
		summary:
			"The client is expected to make an authorization request " +
			"(also a token request and a optionally a userinfo request when applicable)." +
			" Then the RP should terminate the session by calling the end_session_endpoint (RP-Initiated Logout)," +
			" at this point the conformance suite will render the front channel logout page and " +
			" then the RP is expected to handle post logout URI redirect." +
			" Corresponds to rp-frontchannel-rpinitlogout in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		if (
			this.receivedAuthorizationRequest &&
			this.receivedEndSessionRequest &&
			this.receivedFrontChannelLogoutCompletedCallback
		) {
			await this.fireTestFinished();
			return true;
		}
		return false;
	}
}

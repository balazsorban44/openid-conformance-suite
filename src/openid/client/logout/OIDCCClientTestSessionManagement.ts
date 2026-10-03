import type { PublishTestModule } from "../../../framework/index.ts";
import { AbstractOIDCCClientLogoutTest } from "./AbstractOIDCCClientLogoutTest.ts";

export class OIDCCClientTestSessionManagement extends AbstractOIDCCClientLogoutTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-session-management",
		displayName: "OIDCC: Relying party test, session management",
		summary:
			"The client is expected to make an authorization request " +
			"(also a token request and a optionally a userinfo request when applicable)," +
			" then check session status expecting unchanged " +
			" (send at least one http request to check_session_iframe and at least one postMessage call)," +
			" then terminate the session by calling the end_session_endpoint (RP-Initiated Logout)," +
			" then Handle Post Logout URI Redirect, " +
			" then send a postMessage call to check_session_iframe and" +
			" postMessage returns 'changed'." +
			" Corresponds to rp-init-logout-session in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	/**
	 * This test expects at least one postMessage call to check_session_iframe before logout
	 * and one after logout
	 * Number of allowed postMessage calls before logout is unlimited
	 * @return
	 */
	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		if (
			this.receivedAuthorizationRequest &&
			this.receivedEndSessionRequest &&
			this.receivedCheckSessionRequestBeforeLogout &&
			this.receivedCheckSessionRequestAfterLogout
		) {
			await this.fireTestFinished();
			return true;
		}
		return false;
	}

	protected override async configureServerConfiguration(): Promise<void> {
		await super.configureServerConfiguration();
		this.expose("check_session_iframe", this.env.getString("base_url") + "/check_session_iframe");
	}
}

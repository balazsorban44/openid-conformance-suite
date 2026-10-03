import { Status, TestFailureException, args, sleep, type PublishTestModule } from "../../../framework/index.ts";
import { AbstractOIDCCClientFrontChannelLogoutTest } from "./AbstractOIDCCClientFrontChannelLogoutTest.ts";

/**
 * The difference between this one and OIDCCClientTestFrontChannelLogoutRPInitiated is:
 * - This test does not wait for the RP to call the end_session_endpoint
 * - Prompts the tester to click the proceed button to view the front channel logout page
 */
export class OIDCCClientTestFrontChannelLogoutOPInitiated extends AbstractOIDCCClientFrontChannelLogoutTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-rp-frontchannel-opinitlogout",
		displayName: "OIDCC: Relying party test, OP initiated front channel logout.",
		summary:
			"The client is expected to make an authorization request " +
			"(also a token request and a optionally a userinfo request when applicable)," +
			" then the tester will be prompted to visit the OP initiated logout page" +
			" then the RP is expected to handle post logout URI redirect." +
			" This is a new test with no equivalent in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected isAuthorizationCodeRequestUnexpected(): boolean {
		return this.responseType.includesIdToken();
	}

	protected override async handleAuthorizationEndpointRequest(requestId: string): Promise<Response> {
		if (this.isAuthorizationCodeRequestUnexpected()) {
			this.waitAndSendLogoutRequest();
		}
		return super.handleAuthorizationEndpointRequest(requestId);
	}

	protected override async authorizationCodeGrantType(requestId: string): Promise<Response> {
		if (this.isAuthorizationCodeRequestUnexpected()) {
			throw new TestFailureException(this.getId(), "Token request is unexpected for this test");
		} else {
			this.waitAndSendLogoutRequest();
		}
		return super.authorizationCodeGrantType(requestId);
	}

	protected async sendFrontChannelLogoutRequest(): Promise<void> {
		await this.createFrontChannelLogoutRequestUrl();
		await this.performRedirect();
	}

	protected async performRedirect(): Promise<void> {
		const redirectTo = this.env.getString("base_url") + "/frontchannel_logout_handler";

		this.eventLog.log(
			this.getName(),
			args("msg", "Redirecting to front channel logout handler", "redirect_to", redirectTo, "http", "redirect"),
		);

		await this.setStatus(Status.WAITING);
		this.browser.goToUrl(redirectTo);
	}

	protected waitAndSendLogoutRequest(): void {
		this.getTestExecutionManager().runInBackground(async () => {
			await sleep(2 * 1000, this.getTestExecutionManager().signal);
			if (this.getStatus() === Status.WAITING) {
				await this.setStatus(Status.RUNNING);
				await this.sendFrontChannelLogoutRequest();
			}
			return "done";
		});
	}
}

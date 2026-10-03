import { ExpectRedirectUriHasBeenCalled } from "../condition/client/ExpectRedirectUriHasBeenCalled.ts";
import { ConditionResult, sleep, Status, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

export class OIDCCEnsurePostRequestSucceeds extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-ensure-post-request-succeeds",
		displayName: "OIDCC: ensure POST request succeeds.",
		summary:
			"The test makes the call to the authorization endpoint as a POST request. The authentication should " +
			"complete successfully and the authorization server is expected to call the redirect_uri URL within 30 seconds.",
		profile: "OIDCC",
	};

	protected SECONDS_TO_WAIT_FOR_CALLBACK = 30;

	protected startingShutdown = false;

	// Java overloads redirect(String) (POST) and redirect(String, String)
	protected override redirect(redirectTo: string, method?: string): void {
		this.browser.goToUrl(redirectTo, null, method === undefined ? "POST" : method);
		this.startWaitingForTimeout();
	}

	// Java overrides performRedirect() (no argument) to use POST
	protected override async performRedirect(method?: string): Promise<void> {
		await super.performRedirect(method === undefined ? "POST" : method);
	}

	protected startWaitingForTimeout(): void {
		this.startingShutdown = true;
		this.getTestExecutionManager().runInBackground(async () => {
			await sleep(this.SECONDS_TO_WAIT_FOR_CALLBACK * 1000, this.getTestExecutionManager().signal);
			if (this.getStatus() === Status.WAITING) {
				await this.setStatus(Status.RUNNING);
				await this.callAndContinueOnFailure(ExpectRedirectUriHasBeenCalled, ConditionResult.WARNING, "OIDCC-3.1.2.1");
				await this.fireTestFinished();
			}
			return "done";
		});
	}
}

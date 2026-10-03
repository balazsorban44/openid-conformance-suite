import { AddPromptLoginToAuthorizationEndpointRequest } from "../condition/client/AddPromptLoginToAuthorizationEndpointRequest.ts";
import { CheckSecondIdTokenAuthTimeIsLaterIfPresent } from "../condition/client/CheckSecondIdTokenAuthTimeIsLaterIfPresent.ts";
import { ExpectSecondLoginPage } from "../condition/client/ExpectSecondLoginPage.ts";
import { WaitForOneSecond } from "../condition/client/WaitForOneSecond.ts";
import { ConditionResult, Status, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-prompt-login.json
export class OIDCCPromptLogin extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-prompt-login",
		displayName: "OIDCC: prompt=login",
		summary:
			"This test calls the authorization endpoint test twice. The second time it will include prompt=login, so that the authorization server is required to ask the user to login a second time. If auth_time is present in the id_tokens, the value from the second login must be later than the time in the original token. A screenshot of the second authorization should be uploaded.",
		profile: "OIDCC",
	};

	private firstTime = true;

	protected override currentClientString(): string {
		return this.firstTime ? "" : "Second authorization: ";
	}

	protected override async createPlaceholder(): Promise<void> {
		// asking the user for a screenshot of the second login seems a little pointless as there's no way anyone
		// can verify it's from the second login, not the first.
		// It would seem more sensible to have tests that make essential claims for auth_time
		await this.callAndStopOnFailure(ExpectSecondLoginPage, "OIDCC-3.1.2.1");

		this.env.putString("error_callback_placeholder", this.env.getString("expect_second_login_page"));
	}

	protected override async createAuthorizationRequest(): Promise<void> {
		if (this.firstTime) {
			// capture id_token from first authentication for later comparison (we don't care if it's from
			// the authorization endpoint or the token endpoint)
			this.env.mapKey("id_token", "first_id_token");
			await super.createAuthorizationRequest();
		} else {
			this.env.unmapKey("id_token");
			// make sure the auth definitely happens at least 1 second after the original one, so auth_time will be different
			await this.callAndStopOnFailure(WaitForOneSecond);
			await this.call(
				this.createAuthorizationRequestSequence().then(
					this.condition(AddPromptLoginToAuthorizationEndpointRequest).requirements("OIDCC-3.1.2.1", "OIDCC-15.1"),
				),
			);
		}
	}

	// Java: protected final void performRedirect() (only the no-argument overload is overridden)
	protected override async performRedirect(method?: string): Promise<void> {
		if (method !== undefined) {
			await super.performRedirect(method);
			return;
		}
		if (this.firstTime) {
			await super.performRedirect();
		} else {
			await super.performRedirectWithPlaceholder();
		}
	}

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		if (this.firstTime) {
			this.firstTime = false;
			// do the process again, but with prompt=login this time
			await this.performAuthorizationFlow();
		} else {
			await this.callAndContinueOnFailure(
				CheckSecondIdTokenAuthTimeIsLaterIfPresent,
				ConditionResult.FAILURE,
				"OIDCC-2",
			);
			await this.setStatus(Status.WAITING);
			this.waitForPlaceholders();
		}
	}

	override async cleanup(): Promise<void> {
		this.firstTime = true; // to avoid any blocks created in cleanup being prefixed in currentClientString()
		await super.cleanup();
	}
}

import { AddMaxAge1ToAuthorizationEndpointRequest } from "../condition/client/AddMaxAge1ToAuthorizationEndpointRequest.ts";
import { CheckIdTokenAuthTimeClaimPresentDueToMaxAge } from "../condition/client/CheckIdTokenAuthTimeClaimPresentDueToMaxAge.ts";
import { CheckIdTokenAuthTimeIsRecentIfPresent } from "../condition/client/CheckIdTokenAuthTimeIsRecentIfPresent.ts";
import { CheckSecondIdTokenAuthTimeIsLaterIfPresent } from "../condition/client/CheckSecondIdTokenAuthTimeIsLaterIfPresent.ts";
import { ExpectSecondLoginPage } from "../condition/client/ExpectSecondLoginPage.ts";
import { WaitFor2Seconds } from "../condition/client/WaitFor2Seconds.ts";
import { ConditionResult, Status, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Req_max_age=1
// https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-Req-max_age=1.json
export class OIDCCMaxAge1 extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-max-age-1",
		displayName: "OIDCC: max-age=1",
		summary:
			"This test calls the authorization endpoint test twice. The second time it waits 1 second and includes max_age=1, so that the authorization server is required to ask the user to login a second time and must return an auth_time claim in the second id_token. A screenshot of the second authorization should be uploaded.",
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
			// we're sending max_age=2, so after 1 second the previous authentication is just still valid - so wait for
			// 2 seconds
			await this.callAndStopOnFailure(WaitFor2Seconds);
			await this.call(
				this.createAuthorizationRequestSequence().then(
					this.condition(AddMaxAge1ToAuthorizationEndpointRequest).requirements("OIDCC-3.1.2.1", "OIDCC-15.1"),
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

	protected override async performIdTokenValidation(): Promise<void> {
		await super.performIdTokenValidation();

		if (!this.firstTime) {
			await this.callAndContinueOnFailure(
				CheckIdTokenAuthTimeClaimPresentDueToMaxAge,
				ConditionResult.FAILURE,
				"OIDCC-2",
				"OIDCC-3.1.2.1",
			);
			await this.callAndContinueOnFailure(
				CheckSecondIdTokenAuthTimeIsLaterIfPresent,
				ConditionResult.FAILURE,
				"OIDCC-2",
			);
			await this.callAndContinueOnFailure(CheckIdTokenAuthTimeIsRecentIfPresent, ConditionResult.FAILURE, "OIDCC-2");
		}
	}

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		if (this.firstTime) {
			this.firstTime = false;
			// do the process again, but with prompt=login this time
			await this.performAuthorizationFlow();
		} else {
			await this.setStatus(Status.WAITING);
			this.waitForPlaceholders();
		}
	}

	override async cleanup(): Promise<void> {
		this.firstTime = true; // to avoid any blocks created in cleanup being prefixed in currentClientString()
		await super.cleanup();
	}
}

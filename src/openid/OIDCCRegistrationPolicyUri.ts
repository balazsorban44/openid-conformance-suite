import { AddPolicyUriToDynamicRegistrationRequest } from "../condition/client/AddPolicyUriToDynamicRegistrationRequest.ts";
import { CreatePolicyUri } from "../condition/client/CreatePolicyUri.ts";
import { ExpectLoginPageWithPolicyLink } from "../condition/client/ExpectLoginPageWithPolicyLink.ts";
import { type JsonObject, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCDynamicRegistrationTest } from "./AbstractOIDCCDynamicRegistrationTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Registration_policy_uri
export class OIDCCRegistrationPolicyUri extends AbstractOIDCCDynamicRegistrationTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-registration-policy-uri",
		displayName: "OIDCC: dynamic registration with policy URI",
		summary:
			"This test calls the dynamic registration endpoint with a policy URI. This should result in the browser being redirected to a login page with a link to the policy document displayed. To make sure you get a fresh login page, you need to remove any cookies you may have received from the OP before proceeding. A screenshot of the login page should be uploaded.",
		profile: "OIDCC",
	};

	protected override async onConfigure(_config: JsonObject, _baseUrl: string): Promise<void> {
		await this.callAndStopOnFailure(CreatePolicyUri);
	}

	protected override async createPlaceholder(): Promise<void> {
		await this.callAndStopOnFailure(ExpectLoginPageWithPolicyLink, "OIDCR-2");
	}

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		await this.callAndStopOnFailure(AddPolicyUriToDynamicRegistrationRequest);
	}

	protected override async performAuthorizationFlow(): Promise<void> {
		// Redirect to the authorization endpoint to check the appearance of the login page.
		this.eventLog.startBlock("Make request to authorization endpoint");
		await this.createAuthorizationRequest();
		await this.createAuthorizationRedirect();
		await this.performRedirectAndWaitForPlaceholdersOrCallback("login_page_placeholder");
		this.eventLog.endBlock();
	}
}

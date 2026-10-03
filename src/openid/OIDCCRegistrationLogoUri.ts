import { AddLogoUriToDynamicRegistrationRequest } from "../condition/client/AddLogoUriToDynamicRegistrationRequest.ts";
import { CreateLogoUri } from "../condition/client/CreateLogoUri.ts";
import { ExpectLoginPageWithLogo } from "../condition/client/ExpectLoginPageWithLogo.ts";
import { type JsonObject, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCDynamicRegistrationTest } from "./AbstractOIDCCDynamicRegistrationTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Registration_logo_uri
export class OIDCCRegistrationLogoUri extends AbstractOIDCCDynamicRegistrationTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-registration-logo-uri",
		displayName: "OIDCC: dynamic registration with Logo URI",
		summary:
			"This test calls the dynamic registration endpoint with a logo URI. This should result in the browser being redirected to a login page with the RP logo displayed. To make sure you get a fresh login page, you need to remove any cookies you may have received from the OP before proceeding. A screenshot of the login page should be uploaded.",
		profile: "OIDCC",
	};

	protected override async onConfigure(_config: JsonObject, _baseUrl: string): Promise<void> {
		await this.callAndStopOnFailure(CreateLogoUri);
	}

	protected override async createPlaceholder(): Promise<void> {
		await this.callAndStopOnFailure(ExpectLoginPageWithLogo, "OIDCR-2");
	}

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		await this.callAndStopOnFailure(AddLogoUriToDynamicRegistrationRequest);
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

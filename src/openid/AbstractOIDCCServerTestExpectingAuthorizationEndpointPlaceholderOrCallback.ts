import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

export class AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback extends AbstractOIDCCServerTest {
	protected override async performAuthorizationFlow(): Promise<void> {
		this.eventLog.startBlock(this.currentClientString() + "Make request to authorization endpoint");
		await this.createAuthorizationRequest();
		await this.createAuthorizationRedirect();
		await this.performRedirectAndWaitForPlaceholdersOrCallback();
		this.eventLog.endBlock();
	}
}

import { AddQueryToRedirectUriInAuthorizationRequest } from "../condition/client/AddQueryToRedirectUriInAuthorizationRequest.ts";
import { ExpectRedirectUriErrorPage } from "../condition/common/ExpectRedirectUriErrorPage.ts";
import { TestFailureException, type ConditionSequence, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback } from "./AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_redirect_uri_Query_Added
export class OIDCCRedirectUriQueryAdded extends AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-redirect-uri-query-added",
		displayName:
			"OIDCC: request with redirect_uri with query component when registered redirect_uri has no query component",
		summary:
			"This test uses a redirect uri with a query component when the registered redirect uri has no query component. The authorization server should display an error saying the redirect uri is invalid, a screenshot of which should be uploaded.",
		profile: "OIDCC",
	};

	protected override async createPlaceholder(): Promise<void> {
		await this.callAndStopOnFailure(ExpectRedirectUriErrorPage, "OIDCC-3.1.2.1");

		this.env.putString("error_callback_placeholder", this.env.getString("redirect_uri_error"));
	}

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super.createAuthorizationRequestSequence().then(this.condition(AddQueryToRedirectUriInAuthorizationRequest));
	}

	protected override async processCallback(): Promise<void> {
		throw new TestFailureException(
			this.getId(),
			"The authorization server called the registered redirect uri. This should not have happened as the client provided a bad redirect_uri in the request.",
		);
	}
}

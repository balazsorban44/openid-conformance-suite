import { AddQueryToRedirectUri } from "../condition/client/AddQueryToRedirectUri.ts";
import { ReplaceRedirectUriQueryInAuthorizationRequest } from "../condition/client/ReplaceRedirectUriQueryInAuthorizationRequest.ts";
import { ExpectRedirectUriErrorPage } from "../condition/common/ExpectRedirectUriErrorPage.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import {
	TestFailureException,
	type ConditionSequence,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback } from "./AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_redirect_uri_Query_Mismatch
export class OIDCCRedirectUriQueryMismatch extends AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-redirect-uri-query-mismatch",
		displayName: "OIDCC: rejects redirect_uri when query parameter does not match what is registered",
		summary:
			"This test uses a redirect uri with a query component that does not match the query in the registered redirect uri. The authorization server should display an error saying the redirect uri is invalid, a screenshot of which should be uploaded.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async createPlaceholder(): Promise<void> {
		await this.callAndStopOnFailure(ExpectRedirectUriErrorPage, "OIDCC-3.1.2.1");

		this.env.putString("error_callback_placeholder", this.env.getString("redirect_uri_error"));
	}

	protected override async configureDynamicClient(): Promise<void> {
		await this.callAndStopOnFailure(AddQueryToRedirectUri);
		this.exposeEnvString("redirect_uri");
		await super.configureDynamicClient();
	}

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super
			.createAuthorizationRequestSequence()
			.then(this.condition(ReplaceRedirectUriQueryInAuthorizationRequest));
	}

	protected override async processCallback(): Promise<void> {
		throw new TestFailureException(
			this.getId(),
			"The authorization server called the registered redirect uri. This should not have happened as the client provided a bad redirect_uri in the request.",
		);
	}
}

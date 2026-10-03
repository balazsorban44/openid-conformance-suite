import { AddMultipleRedirectUriToDynamicRegistrationRequest } from "../condition/client/AddMultipleRedirectUriToDynamicRegistrationRequest.ts";
import { AuthorizationEndpointRedirectedBackUnexpectedly } from "../condition/client/AuthorizationEndpointRedirectedBackUnexpectedly.ts";
import { ExpectRedirectUriMissingErrorPage } from "../condition/client/ExpectRedirectUriMissingErrorPage.ts";
import { RemoveRedirectUriFromAuthorizationEndpointRequest } from "../condition/client/RemoveRedirectUriFromAuthorizationEndpointRequest.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import {
	ConditionResult,
	type ConditionSequence,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback } from "./AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback.ts";

// Corresponds to OP-redirect_uri-Missing
export class OIDCCEnsureRedirectUriInAuthorizationRequest extends AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-ensure-redirect-uri-in-authorization-request",
		displayName: "OIDCC: ensure redirect URI in authorization request",
		summary:
			"This test registers a client that has two redirect uris and sends a request without redirect_uri to authorization server - this must result in the authorization server showing an error page (a screenshot of which should be uploaded).",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async createPlaceholder(): Promise<void> {
		await this.callAndStopOnFailure(ExpectRedirectUriMissingErrorPage, "OIDCC-3.1.2.1");

		this.env.putString("error_callback_placeholder", this.env.getString("redirect_uri_missing_error"));
	}

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		await this.callAndStopOnFailure(AddMultipleRedirectUriToDynamicRegistrationRequest);
	}

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super
			.createAuthorizationRequestSequence()
			.then(this.condition(RemoveRedirectUriFromAuthorizationEndpointRequest));
	}

	protected override async onAuthorizationCallbackResponse(): Promise<void> {
		await this.callAndContinueOnFailure(AuthorizationEndpointRedirectedBackUnexpectedly, ConditionResult.FAILURE);
		await this.fireTestFinished();
	}
}

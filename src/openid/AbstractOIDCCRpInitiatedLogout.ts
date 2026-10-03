import { AddPostLogoutRedirectUriToDynamicRegistrationRequest } from "../condition/client/AddPostLogoutRedirectUriToDynamicRegistrationRequest.ts";
import { AddPromptNoneToAuthorizationEndpointRequest } from "../condition/client/AddPromptNoneToAuthorizationEndpointRequest.ts";
import { BuildRedirectToEndSessionEndpoint } from "../condition/client/BuildRedirectToEndSessionEndpoint.ts";
import { CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface } from "../condition/client/CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface.ts";
import { CreateEndSessionEndpointRequest } from "../condition/client/CreateEndSessionEndpointRequest.ts";
import { CreatePostLogoutRedirectUri } from "../condition/client/CreatePostLogoutRedirectUri.ts";
import { CreateRandomEndSessionState } from "../condition/client/CreateRandomEndSessionState.ts";
import { args, ConditionResult, Status, type JsonObject } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

export abstract class AbstractOIDCCRpInitiatedLogout extends AbstractOIDCCServerTest {
	protected firstTime = true;
	protected expectingLogoutConfirmation = false;

	protected override currentClientString(): string {
		return this.firstTime ? "" : "Second authorization: ";
	}

	protected override async configureClient(): Promise<void> {
		await this.callAndStopOnFailure(CreatePostLogoutRedirectUri, "OIDCRIL-2", "OIDCRIL-3");
		await super.configureClient();
	}

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		await this.callAndStopOnFailure(AddPostLogoutRedirectUriToDynamicRegistrationRequest, "OIDCRIL-3.1");
	}

	protected override async createAuthorizationRequest(): Promise<void> {
		// python includes the offline_access scope in all authorization requests; I checked with Roland (see 9th June
		// 2020 email) and there was no reason he could remember for doing this and he suspected it was likely a C&P
		// error, so java does not include offline_access.

		if (this.firstTime) {
			await super.createAuthorizationRequest();
		} else {
			// with prompt=none this time
			await this.call(
				this.createAuthorizationRequestSequence().then(
					this.condition(AddPromptNoneToAuthorizationEndpointRequest).requirements("OIDCC-3.1.2.1", "OIDCC-15.1"),
				),
			);
		}
	}

	protected override async onConfigure(config: JsonObject, baseUrl: string): Promise<void> {
		await super.onConfigure(config, baseUrl);
		// use a longer state value to check OP doesn't corrupt it
		this.env.putInteger("requested_state_length", 128);
	}

	protected override async onAuthorizationCallbackResponse(): Promise<void> {
		if (this.firstTime) {
			this.firstTime = false;
			await super.onAuthorizationCallbackResponse();
		} else {
			await this.performGenericAuthorizationEndpointErrorResponseValidation();

			await this.callAndContinueOnFailure(
				CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface,
				ConditionResult.FAILURE,
				"OIDCC-3.1.2.6",
			);

			await this.fireTestFinished();
		}
	}

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		this.eventLog.startBlock("Redirect to end session endpoint & wait for response");
		await this.callAndStopOnFailure(CreateRandomEndSessionState, "OIDCRIL-2", "RFC6749A-A.5");
		await this.callAndStopOnFailure(CreateEndSessionEndpointRequest, "OIDCRIL-2");
		await this.customiseEndSessionEndpointRequest();
		await this.callAndStopOnFailure(BuildRedirectToEndSessionEndpoint, "OIDCRIL-2");
		await this.performRedirectToEndSessionEndpoint();
	}

	protected async customiseEndSessionEndpointRequest(): Promise<void> {}

	protected async performRedirectToEndSessionEndpoint(): Promise<void> {
		const placeholderId = await this.createLogoutPlaceholder();
		const redirectTo = this.env.getString("redirect_to_end_session_endpoint") as string;

		if (placeholderId != null) {
			this.waitForPlaceholders();
		}

		this.eventLog.log(
			this.getName(),
			args("msg", "Redirecting to end session endpoint", "redirect_to", redirectTo, "http", "redirect"),
		);

		this.expectingLogoutConfirmation = true;

		await this.setStatus(Status.WAITING);

		this.browser.goToUrl(redirectTo, placeholderId);
	}

	protected async createLogoutPlaceholder(): Promise<string | null> {
		// override to return a placeholder id if a screenshot is required
		return null;
	}

	override async cleanup(): Promise<void> {
		this.firstTime = true; // to avoid any blocks created in cleanup being prefixed in currentClientString()
		await super.cleanup();
	}
}

import { modelAndView, type ModuleVariantMetadata, type PublishTestModule } from "../../framework/index.ts";
import { CreateAuthorizationEndpointResponseParams } from "../../condition/as/CreateAuthorizationEndpointResponseParams.ts";
import { CreateLoginRequiredErrorResponse } from "../../condition/as/CreateLoginRequiredErrorResponse.ts";
import { EnsureMaxAgeEqualsZeroAndPromptNone } from "../../condition/as/EnsureMaxAgeEqualsZeroAndPromptNone.ts";
import { ResponseMode } from "../../variant/ResponseMode.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestFormPostError extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-form-post-error",
		displayName: "OIDCC: Relying party test. Form post error handling test.",
		summary:
			"The client is expected to construct and send an Authentication Request " +
			" with response mode set to form_post, max_age=0 and prompt=none which results in the " +
			" test suite returning an error because the requested conditions cannot be met. " +
			" The client is expected to consume the HTML form post authorization error response, " +
			" and show an error screen to the user." +
			" Corresponds to rp-response_mode-form_post-error test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ResponseMode, values: ["default"] }],
	};

	protected override async endTestIfRequiredAuthorizationRequestParametersAreMissing(): Promise<void> {
		await this.callAndStopOnFailure(EnsureMaxAgeEqualsZeroAndPromptNone);
	}

	protected override async disallowMaxAge0AndPromptNone(): Promise<void> {
		//do nothing. we want to allow them for this test
	}

	protected override async handleAuthorizationEndpointRequest(requestId: string): Promise<Response> {
		await this.call(
			this.exec().startBlock("Authorization endpoint").mapKey("authorization_endpoint_http_request", requestId),
		);
		this.setAuthorizationEndpointRequestParamsForHttpMethod();
		await this.extractAuthorizationEndpointRequestParameters();
		await this.callAndStopOnFailure(CreateAuthorizationEndpointResponseParams);

		const view = await this.generateFormPostResponse();
		await this.call(this.exec().unmapKey("authorization_endpoint_http_request").endBlock());
		return view;
	}

	/**
	 * we override the response and always return an error response
	 * @return
	 */
	protected override async generateFormPostResponse(): Promise<Response> {
		await this.callAndStopOnFailure(CreateLoginRequiredErrorResponse);

		const errorResponseParams = this.env.getObject(CreateLoginRequiredErrorResponse.ERROR_RESPONSE_PARAMS);
		const formActionUrl = this.env.getString(CreateLoginRequiredErrorResponse.ERROR_RESPONSE_URL);

		return modelAndView("formPostResponseMode", {
			formAction: formActionUrl,
			formParameters: errorResponseParams,
		});
	}

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		let fireTestFinishedCalled = false;
		if (this.receivedAuthorizationRequest) {
			await this.fireTestFinished();
			fireTestFinishedCalled = true;
		}
		return fireTestFinishedCalled;
	}
}

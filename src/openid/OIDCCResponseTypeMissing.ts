import { CheckCallbackContentTypeIsFormUrlEncoded } from "../condition/client/CheckCallbackContentTypeIsFormUrlEncoded.ts";
import { CheckCallbackHttpMethodIsPost } from "../condition/client/CheckCallbackHttpMethodIsPost.ts";
import { CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType } from "../condition/client/CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType.ts";
import { RejectAuthCodeInUrlQuery } from "../condition/client/RejectAuthCodeInUrlQuery.ts";
import { RejectErrorInUrlQuery } from "../condition/client/RejectErrorInUrlQuery.ts";
import { SetAuthorizationEndpointRequestResponseTypeFromEnvironment } from "../condition/client/SetAuthorizationEndpointRequestResponseTypeFromEnvironment.ts";
import { ExpectResponseTypeMissingErrorPage } from "../condition/common/ExpectResponseTypeMissingErrorPage.ts";
import { ConditionResult, type ConditionSequence, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback } from "./AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback.ts";

// Corresponds to https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-Response-Missing.json
export class OIDCCResponseTypeMissing extends AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-response-type-missing",
		displayName: "OIDCC: response type missing",
		summary:
			"This test sends an authorization request that is missing the response_type parameter. The authorization server must either redirect back with an 'unsupported_response_type' or 'invalid_request' error, or must display an error saying the response type is missing, a screenshot of which should be uploaded.",
		profile: "OIDCC",
	};

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super
			.createAuthorizationRequestSequence()
			.skip(SetAuthorizationEndpointRequestResponseTypeFromEnvironment, "Miss out the response_type");
	}

	protected override async createPlaceholder(): Promise<void> {
		await this.callAndStopOnFailure(ExpectResponseTypeMissingErrorPage, "RFC6749-3.1.1");

		this.env.putString("error_callback_placeholder", this.env.getString("response_type_missing_error"));
	}

	protected override async processCallback(): Promise<void> {
		this.eventLog.startBlock(this.currentClientString() + "Verify authorization endpoint response");

		if (this.formPost) {
			this.env.mapKey("authorization_endpoint_response", "callback_body_form_params");
			await this.callAndContinueOnFailure(CheckCallbackHttpMethodIsPost, ConditionResult.FAILURE, "OAuth2-FP-2");
			await this.callAndContinueOnFailure(
				CheckCallbackContentTypeIsFormUrlEncoded,
				ConditionResult.FAILURE,
				"OAuth2-FP-2",
			);
			await this.callAndContinueOnFailure(RejectAuthCodeInUrlQuery, ConditionResult.FAILURE, "OIDCC-3.3.2.5");
			await this.callAndContinueOnFailure(RejectErrorInUrlQuery, ConditionResult.FAILURE, "OAuth2-RT-5");
		} else {
			// response must be in url query as we didn't specify a response_type
			this.env.mapKey("authorization_endpoint_response", "callback_query_params");
		}

		await this.performGenericAuthorizationEndpointErrorResponseValidation();
		await this.callAndContinueOnFailure(
			CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType,
			ConditionResult.FAILURE,
			"RFC6749-3.1.1",
		);

		this.eventLog.endBlock();
		await this.fireTestFinished();
	}
}

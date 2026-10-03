import { CallUserInfoEndpointWithBearerTokenInBody } from "../condition/client/CallUserInfoEndpointWithBearerTokenInBody.ts";
import { UserInfoEndpointWithAccessTokenInBodyNotSupported } from "../condition/client/UserInfoEndpointWithAccessTokenInBodyNotSupported.ts";
import { ConditionResult, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCUserInfoTest } from "./AbstractOIDCCUserInfoTest.ts";

// Corresponds to OP-UserInfo-Body
export class OIDCCUserInfoPostBody extends AbstractOIDCCUserInfoTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-userinfo-post-body",
		displayName: "OIDCC: make POST request to UserInfo endpoint with access token in body",
		summary:
			"This test makes an authenticated POST request to the UserInfo endpoint with the access token in the body and validates the response. Support for passing an access token in the request body is not required by the standards - it is acceptable for servers not to implement this form, and the test will complete with a 'warning' if the server returns a http error response.",
		profile: "OIDCC",
	};

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		await this.callUserInfoEndpoint();
		const statusCode = this.env.getInteger("userinfo_endpoint_response_full", "status") as number;
		// HttpStatus.valueOf(statusCode).is2xxSuccessful()
		if (!(statusCode >= 200 && statusCode < 300)) {
			await this.callAndContinueOnFailure(UserInfoEndpointWithAccessTokenInBodyNotSupported, ConditionResult.WARNING);
		} else {
			await this.extractUserInfoResponse();
			await this.validateExtractedUserInfoResponse();
		}
		await this.fireTestFinished();
	}

	protected override async callUserInfoEndpoint(): Promise<void> {
		await this.callAndStopOnFailure(CallUserInfoEndpointWithBearerTokenInBody, "OIDCC-5.3.1");
	}
}

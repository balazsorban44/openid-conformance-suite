import { CallUserInfoEndpoint } from "../condition/client/CallUserInfoEndpoint.ts";
import { EnsureHttpStatusCodeIs200 } from "../condition/client/EnsureHttpStatusCodeIs200.ts";
import { SetResourceMethodToPost } from "../condition/client/SetResourceMethodToPost.ts";
import { ConditionResult, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCUserInfoTest } from "./AbstractOIDCCUserInfoTest.ts";

// Corresponds to OP-UserInfo-Header
export class OIDCCUserInfoPostHeader extends AbstractOIDCCUserInfoTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-userinfo-post-header",
		displayName: "OIDCC: make POST request to UserInfo endpoint with bearer header",
		summary:
			"This test makes an authenticated POST request to the UserInfo endpoint with the access token in a header and validates the response",
		profile: "OIDCC",
	};

	protected override async callUserInfoEndpoint(): Promise<void> {
		await this.callAndStopOnFailure(SetResourceMethodToPost);
		await this.callAndStopOnFailure(CallUserInfoEndpoint, ConditionResult.FAILURE, "OIDCC-5.3.1");
		await this.call(this.exec().mapKey("endpoint_response", "userinfo_endpoint_response_full"));
		await this.callAndContinueOnFailure(EnsureHttpStatusCodeIs200, ConditionResult.FAILURE);
		await this.call(this.exec().unmapKey("endpoint_response"));
	}
}

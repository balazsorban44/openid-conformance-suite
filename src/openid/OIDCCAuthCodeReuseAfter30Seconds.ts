import { CallProtectedResource } from "../condition/client/CallProtectedResource.ts";
import { EnsureHttpStatusCodeIs4xx } from "../condition/client/EnsureHttpStatusCodeIs4xx.ts";
import { WaitFor30Seconds } from "../condition/client/WaitFor30Seconds.ts";
import { ConditionResult, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCAuthCodeReuse } from "./AbstractOIDCCAuthCodeReuse.ts";

// Equivalent of https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_OAuth_2nd_30s
export class OIDCCAuthCodeReuseAfter30Seconds extends AbstractOIDCCAuthCodeReuse {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-codereuse-30seconds",
		displayName: "OIDCC: Authorization code reuse with a 30 second delay",
		summary:
			"This test tries using an authorization code for a second time, 30 seconds after the first use. The server must return an invalid_grant error as the authorization code has already been used. The originally issued access token should be revoked (as per RFC6749-4.1.2) - a warning is issued if the access token still works.",
		profile: "OIDCC",
	};

	protected override async testReuseOfAuthorizationCode(): Promise<void> {
		await this.callAndStopOnFailure(WaitFor30Seconds);
		await super.testReuseOfAuthorizationCode();
	}

	protected override async checkResponse(): Promise<void> {
		await super.checkResponse();
		this.eventLog.endBlock();
		this.eventLog.startBlock(
			"Testing if access token was revoked after authorization code reuse (the AS 'should' have revoked the access token)",
		);
		await this.callAndStopOnFailure(CallProtectedResource, ConditionResult.FAILURE, "RFC6749-4.1.2");
		await this.call(this.exec().mapKey("endpoint_response", "resource_endpoint_response_full"));
		await this.callAndContinueOnFailure(
			EnsureHttpStatusCodeIs4xx,
			ConditionResult.WARNING,
			"RFC6749-4.1.2",
			"RFC6750-3.1",
		);
		await this.call(this.exec().unmapKey("endpoint_response"));
	}
}

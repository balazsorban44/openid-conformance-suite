import { ServerAllowedReusingAuthorizationCode } from "../condition/client/ServerAllowedReusingAuthorizationCode.ts";
import { ConditionResult, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCAuthCodeReuse } from "./AbstractOIDCCAuthCodeReuse.ts";

// Equivalent of https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_OAuth_2nd
export class OIDCCAuthCodeReuse extends AbstractOIDCCAuthCodeReuse {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-codereuse",
		displayName: "OIDCC: Authorization code reuse",
		summary:
			"This test tries using an authorization code for a second time, immediately after the first use. The server should return an invalid_grant error as the authorization code has already been used. If it doesn't, a warning is raised.",
		profile: "OIDCC",
	};

	protected override async checkResponse(): Promise<void> {
		const httpStatus = this.env.getInteger("token_endpoint_response_http_status");
		if (httpStatus === 200) {
			// HttpStatus.SC_OK
			await this.callAndContinueOnFailure(ServerAllowedReusingAuthorizationCode, ConditionResult.WARNING);
		} else {
			await super.checkResponse();
		}
	}
}

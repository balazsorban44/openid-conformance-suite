
import { type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCUserInfoTest } from "./AbstractOIDCCUserInfoTest.ts";

// Corresponds to OP-UserInfo-Endpoint
export class OIDCCUserInfoGet extends AbstractOIDCCUserInfoTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-userinfo-get",
		displayName: "OIDCC: make GET request to UserInfo endpoint",
		summary: "This test makes an authenticated GET request to the UserInfo endpoint and validates the response",
		profile: "OIDCC",
	};
}

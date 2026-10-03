import { AddPromptNoneToAuthorizationEndpointRequest } from "../condition/client/AddPromptNoneToAuthorizationEndpointRequest.ts";
import { type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCSameAuthTwiceServerTest } from "./AbstractOIDCCSameAuthTwiceServerTest.ts";

// Corresponds to https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-prompt-none-LoggedIn.json
export class OIDCCPromptNoneLoggedIn extends AbstractOIDCCSameAuthTwiceServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-prompt-none-logged-in",
		displayName: "OIDCC: prompt=none when logged in",
		summary:
			"This test calls the authorization endpoint test twice. The second time it will include prompt=none, and the authorization server must not request that the user logs in. The test verifies that auth_time (if present) and sub are consistent between the id_tokens from the first and second authorizations.",
		profile: "OIDCC",
	};

	protected override async createSecondAuthorizationRequest(): Promise<void> {
		// with prompt=none this time
		await this.call(
			this.createAuthorizationRequestSequence().then(
				this.condition(AddPromptNoneToAuthorizationEndpointRequest).requirements("OIDCC-3.1.2.1", "OIDCC-15.1"),
			),
		);
	}
}

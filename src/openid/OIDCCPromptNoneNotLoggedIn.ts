import { AddPromptNoneToAuthorizationEndpointRequest } from "../condition/client/AddPromptNoneToAuthorizationEndpointRequest.ts";
import { CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface } from "../condition/client/CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface.ts";
import { ConditionResult, type ConditionSequence, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-prompt-none-NotLoggedIn.json
export class OIDCCPromptNoneNotLoggedIn extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-prompt-none-not-logged-in",
		displayName: "OIDCC: prompt=none when not logged in",
		summary:
			"This test calls the authorization endpoint with prompt=none, expecting that no recent enough authentication is present to enable a silent login and hence the OP will redirect back with an error as per section 3.1.2.6 of OpenID Connect. Please remove any cookies you may have received from the OpenID Provider before proceeding.",
		profile: "OIDCC",
	};

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		// use a longer state value to check OP doesn't corrupt it in the error response
		this.env.putInteger("requested_state_length", 128);
		return super
			.createAuthorizationRequestSequence()
			.then(this.condition(AddPromptNoneToAuthorizationEndpointRequest).requirements("OIDCC-3.1.2.1", "OIDCC-15.1"));
	}

	protected override async onAuthorizationCallbackResponse(): Promise<void> {
		await this.performGenericAuthorizationEndpointErrorResponseValidation();
		await this.callAndContinueOnFailure(
			CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface,
			ConditionResult.FAILURE,
			"OIDCC-3.1.2.6",
		);
		await this.fireTestFinished();
	}
}

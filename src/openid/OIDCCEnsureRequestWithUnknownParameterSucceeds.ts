import { AddExtraFoobarToAuthorizationEndpointRequest } from "../condition/client/AddExtraFoobarToAuthorizationEndpointRequest.ts";
import { type ConditionSequence, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Equivalent of https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Req_NotUnderstood
export class OIDCCEnsureRequestWithUnknownParameterSucceeds extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-ensure-request-with-unknown-parameter-succeeds",
		displayName: "OIDCC: ensure request with unknown parameter succeeds.",
		summary:
			"The test includes the parameter extra=foobar (which is not defined by any specification) in the request to the authorization endpoint, and the authentication must complete successfully with the extra parameter ignored as per RFC6749-3.1 'The authorization server MUST ignore unrecognized request parameters'",
		profile: "OIDCC",
	};

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super.createAuthorizationRequestSequence().then(this.condition(AddExtraFoobarToAuthorizationEndpointRequest).requirements("RFC6749-3.1"));
	}
}

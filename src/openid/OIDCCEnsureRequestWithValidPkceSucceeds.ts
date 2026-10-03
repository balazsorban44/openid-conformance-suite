import { AddCodeVerifierToTokenEndpointRequest } from "../condition/client/AddCodeVerifierToTokenEndpointRequest.ts";
import { SetupPkceAndAddToAuthorizationRequest } from "../sequence/client/SetupPkceAndAddToAuthorizationRequest.ts";
import { type ConditionSequence, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// New test not present in python suite
export class OIDCCEnsureRequestWithValidPkceSucceeds extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-ensure-request-with-valid-pkce-succeeds",
		displayName: "OIDCC: ensure request with valid PKCE succeeds",
		summary:
			"This test makes an authorization request using valid PKCE (RFC7636), which must succeed. OpenID Connect does not require servers to support PKCE (although it is recommended by the OAuth2 security BCP), but as per https://tools.ietf.org/html/rfc6749#section-3.1 'The authorization server MUST ignore unrecognized request parameters' - i.e. whether the server supports PKCE or not, a valid PKCE request must succeed. The reason for this test is that many OpenID Connect clients speculatively use PKCE, and the OAuth2 standard requires that requests from such clients must not fail.",
		profile: "OIDCC",
	};

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super.createAuthorizationRequestSequence().then(new SetupPkceAndAddToAuthorizationRequest());
	}

	protected override async createAuthorizationCodeRequest(): Promise<void> {
		await super.createAuthorizationCodeRequest();
		await this.callAndStopOnFailure(AddCodeVerifierToTokenEndpointRequest, "RFC7636-4.5");
	}
}

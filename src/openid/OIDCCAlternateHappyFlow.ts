import { BuildPlainRedirectToAuthorizationEndpointReorderedParams } from "../condition/client/BuildPlainRedirectToAuthorizationEndpointReorderedParams.ts";
import { ReverseScopeOrderInAuthorizationEndpointRequest } from "../condition/client/ReverseScopeOrderInAuthorizationEndpointRequest.ts";
import { type ConditionSequence, type PublishTestModule } from "../framework/index.ts";
import { OIDCCScopeEmail } from "./OIDCCScopeEmail.ts";

export class OIDCCAlternateHappyFlow extends OIDCCScopeEmail {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-alternate-happy-flow",
		displayName: "OIDCC: alternate happy flow",
		summary:
			"This test performs a happy flow but with the order of the entries in the 'scope' reversed and authorization endpoint query parameters in a different order, to verify the server does not depend on any particular ordering. As per RFC6749 section 3.3, 'If the value contains multiple space-delimited strings, their order does not matter'.",
		profile: "OIDCC",
	};

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super
			.createAuthorizationRequestSequence()
			.then(this.condition(ReverseScopeOrderInAuthorizationEndpointRequest).requirement("RFC6749-3.3"));
	}

	protected override async createAuthorizationRedirect(): Promise<void> {
		await this.callAndStopOnFailure(BuildPlainRedirectToAuthorizationEndpointReorderedParams);
	}
}

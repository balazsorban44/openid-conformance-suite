import { AddClaimsLocalesSeToAuthorizationEndpointRequest } from "../condition/client/AddClaimsLocalesSeToAuthorizationEndpointRequest.ts";
import { type ConditionSequence, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Req_claims_locales
export class OIDCCClaimsLocales extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-claims-locales",
		displayName: "OIDCC: claims_locales test",
		summary:
			"This test calls the authorization endpoint with claims_locale=se, which (as per section 15.1 of the OpenID Connect core spec) must at a minimum not result in errors.",
		profile: "OIDCC",
	};

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super
			.createAuthorizationRequestSequence()
			.then(this.condition(AddClaimsLocalesSeToAuthorizationEndpointRequest).requirements("OIDCC-5.2", "OIDCC-15.1"));
	}
}

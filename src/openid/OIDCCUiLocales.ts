import { AddUiLocalesFromConfigurationToAuthorizationEndpointRequest } from "../condition/client/AddUiLocalesFromConfigurationToAuthorizationEndpointRequest.ts";
import { type ConditionSequence, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Req_ui_locales
export class OIDCCUiLocales extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-ui-locales",
		displayName: "OIDCC: ui_locales test",
		summary:
			"This test includes the ui_locales parameter in the request to the authorization endpoint, with the value set to that provided in the configuration (or 'se' if no value probably). Use of this parameter in the request must not cause an error at the OP. Please remove any cookies you may have received from the OpenID Provider before proceeding. You need to do this so you can check that the login page is displayed using one of the requested locales.",
		profile: "OIDCC",
	};

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super
			.createAuthorizationRequestSequence()
			.then(this.condition(AddUiLocalesFromConfigurationToAuthorizationEndpointRequest).requirements("OIDCC-3.1.2.1"));
	}
}

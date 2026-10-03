import { SetScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile } from "../condition/client/SetScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile.ts";
import { type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCReturnedClaimsServerTest } from "./AbstractOIDCCReturnedClaimsServerTest.ts";

// Corresponds to OP-scope-all
export class OIDCCScopeAll extends AbstractOIDCCReturnedClaimsServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-scope-all",
		displayName: "OIDCC: check all scopes",
		summary: "This test requests authorization with address, email, phone and profile scopes.",
		profile: "OIDCC",
	};

	protected override async skipTestIfScopesNotSupported(): Promise<void> {
		await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile);
		await super.skipTestIfScopesNotSupported();
	}
}

import { SetScopeInClientConfigurationToOpenIdProfile } from "../condition/client/SetScopeInClientConfigurationToOpenIdProfile.ts";
import { type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCReturnedClaimsServerTest } from "./AbstractOIDCCReturnedClaimsServerTest.ts";

// Corresponds to OP-scope-profile
export class OIDCCScopeProfile extends AbstractOIDCCReturnedClaimsServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-scope-profile",
		displayName: "OIDCC: check profile scope",
		summary: "This test requests authorization with profile scope.",
		profile: "OIDCC",
	};

	protected override async skipTestIfScopesNotSupported(): Promise<void> {
		await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenIdProfile);
		await super.skipTestIfScopesNotSupported();
	}
}

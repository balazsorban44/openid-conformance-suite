import { SetScopeInClientConfigurationToOpenIdPhone } from "../condition/client/SetScopeInClientConfigurationToOpenIdPhone.ts";
import { type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCReturnedClaimsServerTest } from "./AbstractOIDCCReturnedClaimsServerTest.ts";

// Corresponds to OP-scope-phone
export class OIDCCScopePhone extends AbstractOIDCCReturnedClaimsServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-scope-phone",
		displayName: "OIDCC: check phone scope",
		summary: "This test requests authorization with phone scope.",
		profile: "OIDCC",
	};

	protected override async skipTestIfScopesNotSupported(): Promise<void> {
		await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenIdPhone);
		await super.skipTestIfScopesNotSupported();
	}
}

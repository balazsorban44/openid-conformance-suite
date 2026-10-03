import { SetScopeInClientConfigurationToOpenIdAddress } from "../condition/client/SetScopeInClientConfigurationToOpenIdAddress.ts";
import { type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCReturnedClaimsServerTest } from "./AbstractOIDCCReturnedClaimsServerTest.ts";

// Corresponds to OP-scope-address
export class OIDCCScopeAddress extends AbstractOIDCCReturnedClaimsServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-scope-address",
		displayName: "OIDCC: check address scope",
		summary: "This test requests authorization with address scope.",
		profile: "OIDCC",
	};

	protected override async skipTestIfScopesNotSupported(): Promise<void> {
		await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenIdAddress);
		await super.skipTestIfScopesNotSupported();
	}
}

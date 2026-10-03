import type { PublishTestModule } from "../../../framework/index.ts";
import { AbstractOIDCCClientTest } from "../AbstractOIDCCClientTest.ts";

export class OIDCCClientTestDiscoveryOpenIDConfiguration extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-discovery-openid-config",
		displayName: "OIDCC: Relying party openid discovery test",
		summary:
			"The client is expected to retrieve and use the OpenID Provider Configuration Information." +
			"Corresponds to rp-discovery-openid-configuration test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		if (this.receivedDiscoveryRequest) {
			await this.fireTestFinished();
			return true;
		}
		return super.finishTestIfAllRequestsAreReceived();
	}
}

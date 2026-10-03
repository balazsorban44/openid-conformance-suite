import type { ModuleVariantMetadata, PublishTestModule } from "../../../framework/index.ts";
import { ClientRegistration } from "../../../variant/ClientRegistration.ts";
import { AbstractOIDCCClientTest } from "../AbstractOIDCCClientTest.ts";

export class OIDCCClientTestDynamicRegistration extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-dynamic-registration",
		displayName: "OIDCC: Relying party dynamic registration test",
		summary:
			"The client is expected to register using the registration endpoint." +
			"Corresponds to rp-registration-dynamic test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		if (this.receivedRegistrationRequest) {
			await this.fireTestFinished();
			return true;
		}
		return false;
	}
}

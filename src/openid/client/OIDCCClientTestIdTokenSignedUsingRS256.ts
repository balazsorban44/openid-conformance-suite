import type { ConditionSequenceClass, PublishTestModule } from "../../framework/index.ts";
import { OIDCCGenerateServerConfigurationIdTokenSigningAlgRS256Only } from "../../condition/as/OIDCCGenerateServerConfigurationIdTokenSigningAlgRS256Only.ts";
import { SetServerSigningAlgToRS256 } from "../../condition/as/SetServerSigningAlgToRS256.ts";
import { OIDCCRegisterClientWithIdTokenSignedResponseAlgRS256 } from "../../sequence/as/OIDCCRegisterClientWithIdTokenSignedResponseAlgRS256.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestIdTokenSignedUsingRS256 extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-idtoken-sig-rs256",
		displayName: "OIDCC: Relying party test. Id token signed using RS256",
		summary:
			"The client is expected to accept an id_token signed using RS256." +
			" Corresponds to rp-id_token-sig-rs256 test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async setServerSigningAlgorithm(): Promise<void> {
		await this.callAndStopOnFailure(SetServerSigningAlgToRS256, "OIDCR-2");
	}

	protected override async configureServerConfiguration(): Promise<void> {
		await this.callAndStopOnFailure(OIDCCGenerateServerConfigurationIdTokenSigningAlgRS256Only);
	}

	protected override getAdditionalClientRegistrationSteps(): ConditionSequenceClass | null {
		return OIDCCRegisterClientWithIdTokenSignedResponseAlgRS256;
	}
}

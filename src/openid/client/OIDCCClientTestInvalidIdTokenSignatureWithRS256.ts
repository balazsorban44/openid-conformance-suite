import type { ConditionSequenceClass, PublishTestModule } from "../../framework/index.ts";
import { InvalidateIdTokenSignature } from "../../condition/as/InvalidateIdTokenSignature.ts";
import { OIDCCGenerateServerConfigurationIdTokenSigningAlgRS256Only } from "../../condition/as/OIDCCGenerateServerConfigurationIdTokenSigningAlgRS256Only.ts";
import { SetServerSigningAlgToRS256 } from "../../condition/as/SetServerSigningAlgToRS256.ts";
import { OIDCCRegisterClientWithIdTokenSignedResponseAlgRS256 } from "../../sequence/as/OIDCCRegisterClientWithIdTokenSignedResponseAlgRS256.ts";
import { AbstractOIDCCClientTestExpectingNothingInvalidIdToken } from "./AbstractOIDCCClientTestExpectingNothingInvalidIdToken.ts";

export class OIDCCClientTestInvalidIdTokenSignatureWithRS256 extends AbstractOIDCCClientTestExpectingNothingInvalidIdToken {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-invalid-sig-rs256",
		displayName: "OIDCC: Relying party test. Invalid id_token signature using RS256.",
		summary:
			"The client must identify the invalid signature and reject the ID Token after doing ID Token validation. The client may skip this validation if the id token was received from the token endpoint as per https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation\n" +
			"Corresponds to rp-id_token-bad-sig-rs256 test in the old test suite",
		profile: "OIDCC",
		configurationFields: ["waitTimeoutSeconds"],
	};

	protected override isInvalidSignature(): boolean {
		return true;
	}

	override async customizeIdTokenSignature(): Promise<void> {
		await this.callAndStopOnFailure(InvalidateIdTokenSignature, "OIDCC-3.1.3.7", "OIDCC-3.2.2.11");
	}

	protected override async configureServerConfiguration(): Promise<void> {
		await this.callAndStopOnFailure(OIDCCGenerateServerConfigurationIdTokenSigningAlgRS256Only);
	}

	protected override async setServerSigningAlgorithm(): Promise<void> {
		await this.callAndStopOnFailure(SetServerSigningAlgToRS256);
	}

	protected override getAdditionalClientRegistrationSteps(): ConditionSequenceClass | null {
		return OIDCCRegisterClientWithIdTokenSignedResponseAlgRS256;
	}

	protected override getAuthorizationCodeGrantTypeErrorMessage(): string {
		return "Client has incorrectly called token_endpoint after receiving an id_token with an invalid signature from the authorization_endpoint.";
	}

	protected override getHandleUserinfoEndpointRequestErrorMessage(): string {
		return "Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid signature.";
	}
}

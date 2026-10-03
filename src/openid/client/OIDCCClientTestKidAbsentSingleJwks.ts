import type { PublishTestModule } from "../../framework/index.ts";
import { OIDCCGenerateServerJWKsSingleSigningKeyWithNoKeyId } from "../../condition/as/OIDCCGenerateServerJWKsSingleSigningKeyWithNoKeyId.ts";
import { SetServerSigningAlgToRS256 } from "../../condition/as/SetServerSigningAlgToRS256.ts";
import { ValidateJwksSequence } from "../../sequence/ValidateJwksSequence.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestKidAbsentSingleJwks extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-kid-absent-single-jwks",
		displayName:
			"OIDCC: Relying party test. Request an ID token and verify its signature using a single matching RSA key provided by the Issuer." +
			" Use of RS256 algorithm is required for this test.",
		summary:
			"Use the single matching key out of the Issuer's published set to verify the ID Tokens signature and accept the ID Token after doing ID Token validation." +
			" Corresponds to rp-id_token-kid-absent-single-jwks test in the old test suite",
		profile: "OIDCC",
		configurationFields: ["waitTimeoutSeconds"],
	};

	protected override async configureServerJWKS(): Promise<void> {
		// deliberately does not add the unusable extra keys the base class publishes: this test's
		// semantics depend on the published JWKS containing exactly one key
		await this.callAndStopOnFailure(OIDCCGenerateServerJWKsSingleSigningKeyWithNoKeyId, "OIDCC-10.1");
	}

	protected override async setServerSigningAlgorithm(): Promise<void> {
		await this.callAndStopOnFailure(SetServerSigningAlgToRS256);
	}

	protected override async validateConfiguredServerJWKS(): Promise<void> {
		await this.call(
			new ValidateJwksSequence("server_jwks", null, "server signing keys", "RFC7517-1.1").allowingPrivateKeys(),
		);
	}
}

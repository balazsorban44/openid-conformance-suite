import type { PublishTestModule } from "../../../framework/index.ts";
import { AbstractOIDCCClientTest } from "../AbstractOIDCCClientTest.ts";

export class OIDCCClientTestSigningKeyRotationJustBeforeSigning extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-signing-key-rotation-just-before-signing",
		displayName: "OIDCC: Relying party signing key rotation test",
		summary:
			"The client is expected to request an ID token and verify its signature by" +
			" fetching keys from the jwks endpoint. Keys will be rotated right before signing the id_token" +
			" so the client needs to refetch the jwks to validate the signature." +
			"Corresponds to rp-key-rotation-op-sign-key-native test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async signIdToken(): Promise<void> {
		//generate a new jwks with new kids
		await super.configureServerJWKS();
		await super.signIdToken();
	}
}

import type { PublishTestModule } from "../../framework/index.ts";
import { OIDCCGenerateServerJWKsMultipleSigningsKeyWithNoKeyIds } from "../../condition/as/OIDCCGenerateServerJWKsMultipleSigningsKeyWithNoKeyIds.ts";
import { SetServerSigningAlgToRS256 } from "../../condition/as/SetServerSigningAlgToRS256.ts";
import { ValidateJwksSequence } from "../../sequence/ValidateJwksSequence.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestKidAbsentMultipleMatchingKeysInJwks extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-kid-absent-multiple-jwks",
		displayName: "OIDCC: Relying party test. Server JWKS contains multiple possible keys but no 'kid's ",
		summary:
			"This test always uses RS256 signing algorithm. " +
			"Identify that the 'kid' value is missing from the JOSE header and that the Issuer publishes " +
			"multiple keys in its JWK Set document (referenced by 'jwks_uri'). " +
			"The RP can do one of two things; " +
			"reject the ID Token since it can not by using the kid determined which key to use to verify the signature. " +
			"Or it can just test all possible keys and hit upon one that works, which it will in this case." +
			" Corresponds to rp-id_token-kid-absent-multiple-jwks test in the old test suite",
		profile: "OIDCC",
		configurationFields: ["waitTimeoutSeconds"],
	};

	protected override async configureServerJWKS(): Promise<void> {
		// deliberately does not add the unusable extra keys the base class publishes: this test's
		// semantics depend on exactly which keys are in the published JWKS
		await this.callAndStopOnFailure(OIDCCGenerateServerJWKsMultipleSigningsKeyWithNoKeyIds, "OIDCC-10.1");
	}

	protected override async validateConfiguredServerJWKS(): Promise<void> {
		await this.call(
			new ValidateJwksSequence("server_jwks", null, "server signing keys", "RFC7517-1.1").allowingPrivateKeys(),
		);
	}

	/**
	 * this test would not work with HS* or none, so always requiring RS256
	 */
	protected override async setServerSigningAlgorithm(): Promise<void> {
		await this.callAndStopOnFailure(SetServerSigningAlgToRS256);
	}

	/**
	 * For this test the client may or may not respond.
	 * @param requestId
	 * @return
	 */
	protected override async handleAuthorizationEndpointRequest(requestId: string): Promise<Response> {
		const returnValue = await super.handleAuthorizationEndpointRequest(requestId);
		if (this.responseType.includesIdToken()) {
			this.startWaitingForTimeout();
		}
		return returnValue;
	}

	/**
	 * For this test the client may or may not respond.
	 * @param requestId
	 * @return
	 */
	protected override async authorizationCodeGrantType(requestId: string): Promise<Response> {
		const returnValue = await super.authorizationCodeGrantType(requestId);
		this.startWaitingForTimeout();
		return returnValue;
	}
}

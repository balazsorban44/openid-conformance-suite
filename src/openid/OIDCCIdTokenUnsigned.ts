import { AddIdTokenSigningAlgNoneToDynamicRegistrationRequest } from "../condition/client/AddIdTokenSigningAlgNoneToDynamicRegistrationRequest.ts";
import { CheckIdTokenSignatureAlgorithm } from "../condition/client/CheckIdTokenSignatureAlgorithm.ts";
import { OIDCCCheckIdTokenSigningAlgValuesSupportedAlgNone } from "../condition/client/OIDCCCheckIdTokenSigningAlgValuesSupportedAlgNone.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ResponseType } from "../variant/ResponseType.ts";
import { ConditionResult, type ModuleVariantMetadata, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to OPIdToken-none
export class OIDCCIdTokenUnsigned extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-idtoken-unsigned",
		displayName: "OIDCC: check ID token with no signature",
		summary: 'This test requests an ID token signed with "none".',
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [
			{ parameter: ClientRegistration, values: ["static_client"] },
			{ parameter: ResponseType, values: ["code id_token", "code id_token token", "id_token", "id_token token"] },
		],
	};

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		await this.callAndStopOnFailure(AddIdTokenSigningAlgNoneToDynamicRegistrationRequest);
	}

	protected override async performIdTokenValidation(): Promise<void> {
		await this.callAndContinueOnFailure(CheckIdTokenSignatureAlgorithm, ConditionResult.FAILURE, "OIDCC-3.1.3.7");
	}

	protected override async skipTestIfSigningAlgorithmNotSupported(): Promise<void> {
		if (this.serverSupportsDiscovery()) {
			await this.callAndContinueOnFailure(OIDCCCheckIdTokenSigningAlgValuesSupportedAlgNone, ConditionResult.INFO);

			const idTokenSigningAlgSupportedFlag = this.env.getBoolean("id_token_signing_alg_not_supported_flag");
			if (idTokenSigningAlgSupportedFlag != null && idTokenSigningAlgSupportedFlag) {
				this.fireTestSkipped(
					"The discovery endpoint 'id_token_signing_alg_values_supported' doesn't support 'none' algorithm; this cannot be tested (which is acceptable for certification, servers are not required to support 'none'",
				);
			}
		}
	}
}

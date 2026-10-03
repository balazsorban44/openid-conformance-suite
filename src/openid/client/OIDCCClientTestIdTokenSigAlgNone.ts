import {
	Status,
	type ConditionSequenceClass,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../../framework/index.ts";
import { EnsureResponseTypeIsCode } from "../../condition/as/EnsureResponseTypeIsCode.ts";
import { SetServerSigningAlgToNone } from "../../condition/as/SetServerSigningAlgToNone.ts";
import { SignIdTokenWithAlgNone } from "../../condition/as/SignIdTokenWithAlgNone.ts";
import { OIDCCRegisterClientWithIdTokenSignedResponseAlgNone } from "../../sequence/as/OIDCCRegisterClientWithIdTokenSignedResponseAlgNone.ts";
import { ResponseType } from "../../variant/ResponseType.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

/**
 * As per https://bitbucket.org/openid/connect/issues/1214/certification-remove-requirement-for-rp-to
 * this test should pass with a warning result even if alg none is not supported by the client.
 * If it's not supported we will not receive a userinfo request and the test will transition into
 * finished state after a timeout
 */
export class OIDCCClientTestIdTokenSigAlgNone extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-idtoken-sig-none",
		displayName: "OIDCC: Relying party test. Use code flow to retrieve an unsigned id_token",
		summary:
			"The client can either accept the unsigned id_token obtained using code flow and send a userinfo request to " +
			"complete the test or reject the unsigned id_token and stop without sending a userinfo request. " +
			"If a userinfo request is not received then the test will transition into 'skipped'' state after a timeout." +
			" Corresponds to rp-id_token-sig-none test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [
			{
				parameter: ResponseType,
				values: ["code id_token", "code id_token token", "code token", "id_token", "id_token token"],
			},
		],
	};

	protected override async setServerSigningAlgorithm(): Promise<void> {
		await this.callAndStopOnFailure(SetServerSigningAlgToNone);
	}

	protected override async signIdToken(): Promise<void> {
		await this.callAndStopOnFailure(SignIdTokenWithAlgNone);
	}

	protected override async validateResponseTypeAuthorizationRequestParameter(): Promise<void> {
		await this.callAndStopOnFailure(EnsureResponseTypeIsCode, "OIDCR-2");
	}

	protected override getAdditionalClientRegistrationSteps(): ConditionSequenceClass | null {
		return OIDCCRegisterClientWithIdTokenSignedResponseAlgNone;
	}

	protected override async authorizationCodeGrantType(requestId: string): Promise<Response> {
		const valueFromSuper = await super.authorizationCodeGrantType(requestId);
		this.startWaitingForTimeout();
		return valueFromSuper;
	}

	/**
	 * if a userinfo request is not received, set result to WARNING and finish the test
	 */
	protected override startWaitingForTimeout(): void {
		this.getTestExecutionManager().scheduleInBackground(async () => {
			if (this.getStatus() === Status.WAITING) {
				await this.setStatus(Status.RUNNING);
				this.fireTestSkipped(
					"Client did not send a userinfo request after receiving an unsigned id_token. As clients are not required to support unsigned (alg: none) id_tokens this is okay.",
				);
			}
			return "done";
		}, this.waitTimeoutSeconds * 1000);
	}
}

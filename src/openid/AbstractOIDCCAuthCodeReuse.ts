import { CallTokenEndpointAndReturnFullResponse } from "../condition/client/CallTokenEndpointAndReturnFullResponse.ts";
import { CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB } from "../condition/client/CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB.ts";
import { CheckErrorFromTokenEndpointResponseErrorInvalidGrant } from "../condition/client/CheckErrorFromTokenEndpointResponseErrorInvalidGrant.ts";
import { CheckTokenEndpointHttpStatus400 } from "../condition/client/CheckTokenEndpointHttpStatus400.ts";
import { CheckTokenEndpointReturnedJsonContentType } from "../condition/client/CheckTokenEndpointReturnedJsonContentType.ts";
import { ValidateErrorDescriptionFromTokenEndpointResponseError } from "../condition/client/ValidateErrorDescriptionFromTokenEndpointResponseError.ts";
import { ValidateErrorFromTokenEndpointResponseError } from "../condition/client/ValidateErrorFromTokenEndpointResponseError.ts";
import { ValidateErrorUriFromTokenEndpointResponseError } from "../condition/client/ValidateErrorUriFromTokenEndpointResponseError.ts";
import { CreateJWTClientAuthenticationAssertionAndAddToTokenEndpointRequest } from "../sequence/client/CreateJWTClientAuthenticationAssertionAndAddToTokenEndpointRequest.ts";
import { ResponseType } from "../variant/ResponseType.ts";
import { ConditionResult, type ConditionSequenceClass, type ModuleVariantMetadata } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

export abstract class AbstractOIDCCAuthCodeReuse extends AbstractOIDCCServerTest {
	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ResponseType, values: ["id_token", "id_token token"] }],
	};

	private generateNewClientAssertionSteps: ConditionSequenceClass | null = null;

	// @VariantSetup(parameter = ClientAuthType.class, value = "client_secret_jwt") - registered in the base class
	override setupClientSecretJwt(): void {
		super.setupClientSecretJwt();
		this.generateNewClientAssertionSteps = CreateJWTClientAuthenticationAssertionAndAddToTokenEndpointRequest;
	}

	// @VariantSetup(parameter = ClientAuthType.class, value = "private_key_jwt") - registered in the base class
	override setupPrivateKeyJwt(): void {
		super.setupPrivateKeyJwt();
		this.generateNewClientAssertionSteps = CreateJWTClientAuthenticationAssertionAndAddToTokenEndpointRequest;
	}

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		await this.testReuseOfAuthorizationCode();
		await super.onPostAuthorizationFlowComplete();
	}

	protected async testReuseOfAuthorizationCode(): Promise<void> {
		this.eventLog.startBlock("Attempting reuse of authorization code");

		if (this.generateNewClientAssertionSteps != null) {
			this.mapClientAuthKeys("token_endpoint_request_form_parameters", "token_endpoint_request_headers");
			await this.call(this.sequence(this.generateNewClientAssertionSteps));
			this.unmapClientAuthKeys();
		}

		await this.callAndStopOnFailure(CallTokenEndpointAndReturnFullResponse, ConditionResult.FAILURE);
		await this.checkResponse();
		this.eventLog.endBlock();
	}

	protected async checkResponse(): Promise<void> {
		await this.callAndContinueOnFailure(CheckTokenEndpointHttpStatus400, ConditionResult.FAILURE, "OIDCC-3.1.3.4");
		await this.callAndContinueOnFailure(
			CheckTokenEndpointReturnedJsonContentType,
			ConditionResult.FAILURE,
			"OIDCC-3.1.3.4",
		);
		// https://github.com/rohe/oidctest/blob/41ef7a64fd8a24d8150077781dac93a11a0c5023/test_tool/cp/test_op/flows/OP-OAuth-2nd.json#L52 allowed other error codes,
		// and https://github.com/rohe/oidctest/blob/41ef7a64fd8a24d8150077781dac93a11a0c5023/test_tool/cp/test_op/flows/OP-OAuth-2nd-Revokes.json#L51 different ones again -
		// we go with the "what the RFC actually says" case.
		await this.callAndContinueOnFailure(
			CheckErrorFromTokenEndpointResponseErrorInvalidGrant,
			ConditionResult.FAILURE,
			"RFC6749-5.2",
		);
		await this.callAndContinueOnFailure(
			ValidateErrorFromTokenEndpointResponseError,
			ConditionResult.FAILURE,
			"RFC6749-5.2",
		);
		await this.callAndContinueOnFailure(
			CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB,
			ConditionResult.WARNING,
			"RFC6749-5.2",
		);
		await this.callAndContinueOnFailure(
			ValidateErrorDescriptionFromTokenEndpointResponseError,
			ConditionResult.FAILURE,
			"RFC6749-5.2",
		);
		await this.callAndContinueOnFailure(
			ValidateErrorUriFromTokenEndpointResponseError,
			ConditionResult.FAILURE,
			"RFC6749-5.2",
		);
	}
}

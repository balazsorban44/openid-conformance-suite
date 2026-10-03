import {
	AbstractConditionSequence,
	ConditionResult,
	type ConditionClass,
	type ConditionSequenceClass,
} from "../../framework/index.ts";
import { AddScopeToTokenEndpointRequest } from "../../condition/client/AddScopeToTokenEndpointRequest.ts";
import { CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse } from "../../condition/client/CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse.ts";
import { CallTokenEndpointAndReturnFullResponse } from "../../condition/client/CallTokenEndpointAndReturnFullResponse.ts";
import { CheckErrorFromTokenEndpointResponseErrorInvalidGrant } from "../../condition/client/CheckErrorFromTokenEndpointResponseErrorInvalidGrant.ts";
import { CheckTokenEndpointHttpStatus400 } from "../../condition/client/CheckTokenEndpointHttpStatus400.ts";
import { CheckTokenEndpointReturnedJsonContentType } from "../../condition/client/CheckTokenEndpointReturnedJsonContentType.ts";
import { CreateRefreshTokenRequest } from "../../condition/client/CreateRefreshTokenRequest.ts";
import { ValidateErrorFromTokenEndpointResponseError } from "../../condition/client/ValidateErrorFromTokenEndpointResponseError.ts";
import { CreateDpopProofSteps } from "./CreateDpopProofSteps.ts";

export class RefreshTokenRequestExpectingErrorSteps extends AbstractConditionSequence {
	private secondClient: boolean;
	private isDpop: boolean;
	private addClientAuthenticationToTokenEndpointRequest: ConditionSequenceClass;

	constructor(
		secondClient: boolean,
		addClientAuthenticationToTokenEndpointRequest: ConditionSequenceClass,
		isDpop = false,
	) {
		super();
		this.secondClient = secondClient;
		this.isDpop = isDpop;
		this.addClientAuthenticationToTokenEndpointRequest = addClientAuthenticationToTokenEndpointRequest;
	}

	override evaluate(): void {
		this.callAndStopOnFailure(CreateRefreshTokenRequest);
		if (!this.secondClient) {
			this.callAndStopOnFailure(AddScopeToTokenEndpointRequest, "RFC6749-6");
		}

		this.call(
			this.exec()
				.mapKey("request_form_parameters", "token_endpoint_request_form_parameters")
				.mapKey("request_headers", "token_endpoint_request_headers"),
		);
		this.call(this.sequence(this.addClientAuthenticationToTokenEndpointRequest));
		this.call(this.exec().unmapKey("request_form_parameters").unmapKey("request_headers"));

		if (this.isDpop) {
			this.call(CreateDpopProofSteps.createTokenEndpointDpopSteps());
			this.callAndStopOnFailure(CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse);

			// retry request if token_endpoint_dpop_nonce_error is found
			this.call(this.exec().startBlock("Token endpoint DPoP nonce retry"));

			// repeat conditions in CreateDpopProofSteps.createTokenEndpointDpopSteps() only if token_endpoint_dpop_nonce_error is found
			const seq = CreateDpopProofSteps.createTokenEndpointDpopSteps();
			seq.evaluate();
			const condList = seq
				.getTestExecutionUnits()
				.map(AbstractConditionSequence.actionToConditionClass) as ConditionClass[];
			for (const cond of condList) {
				this.call(
					this.condition(cond).skipIfStringsMissing("token_endpoint_dpop_nonce_error").onSkip(ConditionResult.INFO),
				);
			}

			this.call(
				this.condition(CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse)
					.skipIfStringsMissing("token_endpoint_dpop_nonce_error")
					.onSkip(ConditionResult.INFO),
			);
			this.call(this.exec().endBlock());
		} else {
			this.callAndStopOnFailure(CallTokenEndpointAndReturnFullResponse);
		}

		this.callAndStopOnFailure(ValidateErrorFromTokenEndpointResponseError);
		this.callAndContinueOnFailure(CheckTokenEndpointHttpStatus400, ConditionResult.FAILURE, "OIDCC-3.1.3.4");
		this.callAndContinueOnFailure(CheckTokenEndpointReturnedJsonContentType, ConditionResult.FAILURE, "OIDCC-3.1.3.4");
		this.callAndContinueOnFailure(
			CheckErrorFromTokenEndpointResponseErrorInvalidGrant,
			ConditionResult.FAILURE,
			"RFC6749-5.2",
		);
	}
}

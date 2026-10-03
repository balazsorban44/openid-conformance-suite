import { AbstractConditionSequence, ConditionResult } from "../../framework/index.ts";
import { CallDynamicRegistrationEndpoint } from "../../condition/client/CallDynamicRegistrationEndpoint.ts";
import { CheckNoErrorFromDynamicRegistrationEndpoint } from "../../condition/client/CheckNoErrorFromDynamicRegistrationEndpoint.ts";
import { EnsureContentTypeJson } from "../../condition/client/EnsureContentTypeJson.ts";
import { EnsureHttpStatusCodeIs201 } from "../../condition/client/EnsureHttpStatusCodeIs201.ts";
import { ExtractDynamicRegistrationResponse } from "../../condition/client/ExtractDynamicRegistrationResponse.ts";
import { VerifyClientManagementCredentials } from "../../condition/client/VerifyClientManagementCredentials.ts";
import { VerifyDynamicRegistrationResponseClientCredentials } from "../../condition/client/VerifyDynamicRegistrationResponseClientCredentials.ts";

export class CallDynamicRegistrationEndpointAndVerifySuccessfulResponse extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(CallDynamicRegistrationEndpoint, "RFC7591-3.1", "OIDCR-3.2");

		this.call(this.exec().mapKey("endpoint_response", "dynamic_registration_endpoint_response"));

		this.callAndContinueOnFailure(EnsureContentTypeJson, ConditionResult.FAILURE, "OIDCR-3.2");
		this.callAndContinueOnFailure(EnsureHttpStatusCodeIs201, ConditionResult.FAILURE, "OIDCR-3.2");
		this.callAndContinueOnFailure(CheckNoErrorFromDynamicRegistrationEndpoint, ConditionResult.FAILURE, "OIDCR-3.2");
		this.callAndStopOnFailure(ExtractDynamicRegistrationResponse, ConditionResult.FAILURE, "OIDCR-3.2");
		this.callAndContinueOnFailure(VerifyClientManagementCredentials, ConditionResult.FAILURE, "OIDCR-3.2");
		this.callAndContinueOnFailure(
			VerifyDynamicRegistrationResponseClientCredentials,
			ConditionResult.FAILURE,
			"OIDCR-3.2",
		);

		this.call(this.exec().unmapKey("endpoint_response"));
	}
}

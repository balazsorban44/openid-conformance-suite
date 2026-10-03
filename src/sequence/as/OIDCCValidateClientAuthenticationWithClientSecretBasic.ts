import { AbstractConditionSequence, ConditionResult } from "../../framework/index.ts";
import { ExtractClientCredentialsFromBasicAuthorizationHeader } from "../../condition/as/ExtractClientCredentialsFromBasicAuthorizationHeader.ts";
import { ValidateClientIdAndSecret } from "../../condition/as/ValidateClientIdAndSecret.ts";

export class OIDCCValidateClientAuthenticationWithClientSecretBasic extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(ExtractClientCredentialsFromBasicAuthorizationHeader, ConditionResult.FAILURE, "OIDCC-9");

		this.callAndContinueOnFailure(ValidateClientIdAndSecret, ConditionResult.FAILURE, "RFC6749-2.3.1");
	}
}

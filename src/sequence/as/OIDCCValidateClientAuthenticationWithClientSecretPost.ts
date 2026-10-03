import { AbstractConditionSequence, ConditionResult } from "../../framework/index.ts";
import { ExtractClientCredentialsFromFormPost } from "../../condition/as/ExtractClientCredentialsFromFormPost.ts";
import { ValidateClientIdAndSecret } from "../../condition/as/ValidateClientIdAndSecret.ts";

export class OIDCCValidateClientAuthenticationWithClientSecretPost extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndContinueOnFailure(ExtractClientCredentialsFromFormPost, ConditionResult.FAILURE, "OIDCC-9");

		this.callAndContinueOnFailure(ValidateClientIdAndSecret, ConditionResult.FAILURE, "RFC6749-2.3.1");
	}
}

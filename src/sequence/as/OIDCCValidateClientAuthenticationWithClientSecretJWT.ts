import { AbstractConditionSequence, ConditionResult } from "../../framework/index.ts";
import { EnsureClientAssertionSignatureAlgorithmMatchesRegistered } from "../../condition/as/EnsureClientAssertionSignatureAlgorithmMatchesRegistered.ts";
import { EnsureClientAssertionTypeIsJwt } from "../../condition/as/EnsureClientAssertionTypeIsJwt.ts";
import { ExtractClientAssertion } from "../../condition/as/ExtractClientAssertion.ts";
import { ValidateClientAssertionClaims } from "../../condition/as/ValidateClientAssertionClaims.ts";
import { ValidateClientAssertionSignatureWithHMACAlgorithm } from "../../condition/as/ValidateClientAssertionSignatureWithHMACAlgorithm.ts";

export class OIDCCValidateClientAuthenticationWithClientSecretJWT extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndContinueOnFailure(ExtractClientAssertion, ConditionResult.FAILURE, "RFC7523-2.2");
		this.callAndContinueOnFailure(
			EnsureClientAssertionSignatureAlgorithmMatchesRegistered,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);
		this.callAndContinueOnFailure(
			ValidateClientAssertionSignatureWithHMACAlgorithm,
			ConditionResult.FAILURE,
			"OIDCC-9",
		);
		this.callAndContinueOnFailure(EnsureClientAssertionTypeIsJwt, ConditionResult.FAILURE, "RFC7523-2.2");
		this.callAndContinueOnFailure(ValidateClientAssertionClaims, ConditionResult.FAILURE, "RFC7523-3", "OIDCC-9");
	}
}

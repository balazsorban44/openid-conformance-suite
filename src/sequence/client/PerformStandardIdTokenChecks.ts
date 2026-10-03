import { AbstractConditionSequence, ConditionResult } from "../../framework/index.ts";
import { CheckForSubjectInIdToken } from "../../condition/client/CheckForSubjectInIdToken.ts";
import { EnsureIdTokenUpdatedAtValid } from "../../condition/client/EnsureIdTokenUpdatedAtValid.ts";
import { ValidateEncryptedIdTokenHasKid } from "../../condition/client/ValidateEncryptedIdTokenHasKid.ts";
import { ValidateIdToken } from "../../condition/client/ValidateIdToken.ts";
import { ValidateIdTokenACRClaimAgainstRequest } from "../../condition/client/ValidateIdTokenACRClaimAgainstRequest.ts";
import { ValidateIdTokenNonce } from "../../condition/client/ValidateIdTokenNonce.ts";
import { ValidateIdTokenSignature } from "../../condition/client/ValidateIdTokenSignature.ts";
import { ValidateIdTokenStandardClaims } from "../../condition/client/ValidateIdTokenStandardClaims.ts";

// This class is intended to perform all checks that will always be true for an id_token
// It should only contain checks that are obviously correct in all circumstances
// e.g. it cannot require that auth_time is very recent (as the user may have logged in some time ago)
// It can check optional items, so long as it doesn't insist optional items are present (unless they are
// required in a circumstance it can detect based on the environment, e.g. nonce required if the request
// contained a nonce).
export class PerformStandardIdTokenChecks extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndContinueOnFailure(ValidateIdToken, ConditionResult.FAILURE, "OIDCC-3.1.3.7");
		this.callAndContinueOnFailure(ValidateIdTokenStandardClaims, ConditionResult.FAILURE, "OIDCC-5.1");

		// Equivalent of https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#verify_nonce
		// and https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#check_idtoken_nonce
		this.callAndContinueOnFailure(ValidateIdTokenNonce, ConditionResult.FAILURE, "OIDCC-2");

		this.callAndContinueOnFailure(ValidateIdTokenACRClaimAgainstRequest, ConditionResult.FAILURE, "OIDCC-5.5.1.1");

		this.callAndContinueOnFailure(ValidateIdTokenSignature, ConditionResult.FAILURE);
		this.callAndContinueOnFailure(CheckForSubjectInIdToken, ConditionResult.FAILURE, "OIDCC-2");
		this.callAndContinueOnFailure(EnsureIdTokenUpdatedAtValid, ConditionResult.FAILURE, "OIDCC-5.1");

		this.call(
			this.condition(ValidateEncryptedIdTokenHasKid)
				.skipIfElementMissing("id_token", "jwe_header")
				.onFail(ConditionResult.FAILURE)
				.onSkip(ConditionResult.INFO)
				.requirements("OIDCC-10.2", "OIDCC-10.2.1")
				.dontStopOnFailure(),
		);
	}
}

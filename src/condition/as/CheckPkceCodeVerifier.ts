import { AbstractConditionSequence, ConditionResult } from "../../framework/index.ts";
import { EnsureMinimumPkceCodeVerifierEntropy } from "../client/EnsureMinimumPkceCodeVerifierEntropy.ts";
import { EnsureMinimumPkceCodeVerifierLength } from "../client/EnsureMinimumPkceCodeVerifierLength.ts";
import { EnsurePkceCodeVerifierNotUsed } from "../client/EnsurePkceCodeVerifierNotUsed.ts";
import { ValidateCodeVerifierWithS256 } from "./ValidateCodeVerifierWithS256.ts";

export class CheckPkceCodeVerifier extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(ValidateCodeVerifierWithS256, "RFC7636-4.6");
		this.callAndContinueOnFailure(EnsureMinimumPkceCodeVerifierEntropy, ConditionResult.WARNING, "RFC7636-7.1");
		this.callAndContinueOnFailure(EnsureMinimumPkceCodeVerifierLength, ConditionResult.WARNING, "RFC7636-7.1");
		this.callAndContinueOnFailure(EnsurePkceCodeVerifierNotUsed, ConditionResult.FAILURE, "RFC7636-4.1");
	}
}

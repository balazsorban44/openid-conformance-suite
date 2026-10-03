import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { RFC6749AppendixASyntaxUtils } from "../util/RFC6749AppendixASyntaxUtils.ts";

export class EnsureDpopNonceContainsAllowedCharactersOnly extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dpop_proof_claims"] };

	override evaluate(env: Environment): Environment {
		const dpopNonce = env.getString("dpop_proof_claims", "nonce");
		if (dpopNonce == null) {
			this.log("No DPOP nonce required");
		} else {
			if (!RFC6749AppendixASyntaxUtils.isNQCharSequence(dpopNonce)) {
				throw this.error(
					"DPOP nonce contains illegal characters. As per RFC-6749, only NQCHAR characters %x21 / %x23-5B / %x5D-7E are allowed.",
					args("DPOP nonce", dpopNonce),
				);
			}
			this.logSuccess("DPOP nonce does not contain any illegal characters", args("DPOP nonce", dpopNonce));
		}

		return env;
	}
}

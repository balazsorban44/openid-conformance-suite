import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractEnsureMinimumEntropy } from "../AbstractEnsureMinimumEntropy.ts";

export class EnsureMinimumPkceCodeVerifierEntropy extends AbstractEnsureMinimumEntropy {
	/**
	 * https://www.rfc-editor.org/rfc/rfc7636.html#section-7.1
	 *
	 *    The client SHOULD create a "code_verifier" with a minimum of 256 bits
	 *    of entropy.  This can be done by having a suitable random number
	 *    generator create a 32-octet sequence.  The octet sequence can then be
	 *    base64url-encoded to produce a 43-octet URL safe string to use as a
	 *    "code_challenge" that has the required entropy.
	 *
	 * The actual amount of required entropy is 256 bits, but we can't accurately measure entropy so a bit of
	 * slop is allowed for.
	 */
	private readonly requiredEntropy = 180;

	static override pre: EnvironmentRequirements = { required: ["token_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const codeVerifier = env.getString("token_endpoint_request", "body_form_params.code_verifier");
		if (!codeVerifier) {
			throw this.error("Couldn't find code_verifier in token request");
		}
		// UPSTREAM: duplicate (unreachable) check with a copy-pasted message
		if (!codeVerifier) {
			throw this.error("Can't find access token");
		}

		return this.ensureMinimumEntropy(env, codeVerifier, this.requiredEntropy);
	}
}

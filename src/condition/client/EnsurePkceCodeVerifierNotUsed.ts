import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsurePkceCodeVerifierNotUsed extends AbstractCondition {
	private static readonly CACHE_SIZE = 256;
	private static readonly cachedCodes: string[] = [];

	static override pre: EnvironmentRequirements = { required: ["token_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const codeVerifier = env.getString("token_endpoint_request", "body_form_params.code_verifier");

		if (!codeVerifier) {
			throw this.error("Code Verifier not found in request");
		}

		// (Java: synchronized (cachedCodes) - evaluation here is synchronous, so no lock is needed)
		const cachedCodes = EnsurePkceCodeVerifierNotUsed.cachedCodes;
		if (cachedCodes.includes(codeVerifier)) {
			throw this.error("code verifier has been used", args("code verifier", codeVerifier));
		} else {
			if (cachedCodes.length >= EnsurePkceCodeVerifierNotUsed.CACHE_SIZE) {
				cachedCodes.splice(0, 50);
			}
			cachedCodes.push(codeVerifier);
			this.logSuccess("Code verifier has not been used", args("code_verifier", codeVerifier));
		}

		return env;
	}
}

import { createHash } from "node:crypto";
import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ValidateCodeVerifierWithS256 extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		strings: ["code_challenge", "code_challenge_method"],
		required: ["token_endpoint_request"],
	};

	override evaluate(env: Environment): Environment {
		const codeVerifier = env.getString("token_endpoint_request", "body_form_params.code_verifier");

		if (!codeVerifier) {
			throw this.error("Couldn't find code_verifier in token request");
		}

		const codeChallenge = env.getString("code_challenge") as string;
		const codeChallengeMethod = env.getString("code_challenge_method");

		if ("S256" !== codeChallengeMethod) {
			throw this.error("Unexpected code_challenge_method", args("code_challenge_method", codeChallengeMethod));
		}

		// Java: getBytes(US_ASCII) replaces every unmappable character with '?'
		const bytes = Buffer.from(codeVerifier.replace(/[\u0080-\u{10ffff}]/gu, "?"), "ascii");
		const digest = createHash("sha256").update(bytes).digest();
		const calculatedChallenge = digest.toString("base64url");

		if (codeChallenge === calculatedChallenge) {
			this.logSuccess(
				"Validated code_verifier successfully",
				args(
					"code_verifier",
					codeVerifier,
					"code_challenge",
					codeChallenge,
					"code_challenge_method",
					codeChallengeMethod,
				),
			);
			return env;
		} else {
			throw this.error(
				"PKCE validation failed",
				args(
					"expected_code_challenge",
					calculatedChallenge,
					"code_verifier",
					codeVerifier,
					"code_challenge",
					codeChallenge,
					"code_challenge_method",
					codeChallengeMethod,
				),
			);
		}
	}
}

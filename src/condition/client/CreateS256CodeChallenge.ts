import { createHash } from "node:crypto";
import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CreateS256CodeChallenge extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["code_verifier"] };
	static override post: EnvironmentRequirements = { strings: ["code_challenge", "code_challenge_method"] };

	override evaluate(env: Environment): Environment {
		const verifier = env.getString("code_verifier");

		if (!verifier) {
			throw this.error("code_verifier was null or empty");
		}

		const bytes = Buffer.from(verifier, "ascii");
		const digest = createHash("sha256").update(bytes).digest();
		const challenge = digest.toString("base64url");

		env.putString("code_challenge", challenge);
		env.putString("code_challenge_method", "S256");

		this.log("Created code_challenge value", args("code_challenge", challenge));

		return env;
	}
}

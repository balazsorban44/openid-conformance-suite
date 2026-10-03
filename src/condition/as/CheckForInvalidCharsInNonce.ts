import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckForInvalidCharsInNonce extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["nonce"] };

	override evaluate(env: Environment): Environment {
		const invalidCharacters: string[] = [];
		const nonce = env.getString("nonce");

		if (!nonce) {
			throw this.error("nonce is empty");
		}
		// Ensure the nonce contains only URL safe characters.
		for (let i = 0; i < nonce.length; i++) {
			const charAsString = nonce.charAt(i);

			if (!/^[A-Za-z0-9\-_.~]$/.test(charAsString)) {
				if (!invalidCharacters.includes(charAsString)) {
					invalidCharacters.push(charAsString);
				}
			}
		}

		if (invalidCharacters.length > 0) {
			throw this.error(
				"Non URL safe characters found in nonce. This may introduce interoperability issues.",
				args("nonce", nonce, "invalid_chars", invalidCharacters),
			);
		}

		this.logSuccess("Nonce contains only URL safe characters");
		return env;
	}
}

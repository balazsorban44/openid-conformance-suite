import {
	AbstractCondition,
	args,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class CreateRandomCodeVerifier extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["code_verifier"] };

	override evaluate(env: Environment): Environment {
		// https://tools.ietf.org/html/rfc7636#section-4.1
		//
		// code_verifier = high-entropy cryptographic random STRING using the
		// unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
		// from Section 2.3 of [RFC3986], with a minimum length of 43 characters
		// and a maximum length of 128 characters.
		const allowedChars =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ" + // 'A'..'Z'
			"abcdefghijklmnopqrstuvwxyz" + // 'a'..'z'
			"0123456789" + // '0'..'9'
			"-" +
			"." +
			"_" +
			"~";

		// In a real client base64url of SecureRandom would be fine/simpler; we don't
		// use it here as it would not include the . and ~ characters and we want to
		// test the full range of permitted characters

		// test maximum permitted length
		const verifier = RandomStringUtils.next(128, allowedChars);

		env.putString("code_verifier", verifier);

		this.log("Created code_verifier value", args("code_verifier", verifier));

		return env;
	}
}

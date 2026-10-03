import {
	AbstractCondition,
	args,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class CreateRandomNonceValue extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["nonce"] };

	override evaluate(env: Environment): Environment {
		let nonceLength = env.getInteger("requested_nonce_length");
		if (nonceLength == null) {
			nonceLength = 10; // default to a nonce of length 10
		}

		let nonce: string;
		if (nonceLength > 10) {
			// Check that any url safe character can be used when using a longer nonce value
			nonce = RandomStringUtils.nextAlphanumeric(nonceLength - 4) + "-._~";
		} else {
			// this is a more restricted character set than https://tools.ietf.org/html/rfc6749#appendix-A.5 which
			// allows 0x20-0x7E; presumably an attempt to avoid potentially problem prone characters
			nonce = RandomStringUtils.nextAlphanumeric(nonceLength);
		}

		env.putString("nonce", nonce);

		this.log("Created nonce value", args("nonce", nonce, "requested_nonce_length", nonceLength));

		return env;
	}
}

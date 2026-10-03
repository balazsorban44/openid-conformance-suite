import {
	AbstractCondition,
	args,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class CreateRandomStateValue extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["state"] };

	override evaluate(env: Environment): Environment {
		let stateLength = env.getInteger("requested_state_length");
		if (stateLength == null) {
			stateLength = 10; // default to a state of length 10
		}

		let state: string;
		if (stateLength > 10) {
			// as per https://gitlab.com/openid/conformance-suite/-/issues/1226 JWTs are commonly used for state
			// values - we hence check that any url safe character can be used when using a longer state value
			state = RandomStringUtils.nextAlphanumeric(stateLength - 4) + "-._~";
		} else {
			// this is a more restricted character set than https://tools.ietf.org/html/rfc6749#appendix-A.5 which
			// allows 0x20-0x7E; presumably an attempt to avoid potentially problem prone characters
			state = RandomStringUtils.nextAlphanumeric(stateLength);
		}

		env.putString("state", state);

		this.log("Created state value", args("state", state, "requested_state_length", stateLength));

		return env;
	}
}

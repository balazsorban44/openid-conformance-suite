import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckSessionResultIsUnchanged extends AbstractCondition {
	static readonly EXPECTED = "unchanged";

	static override pre: EnvironmentRequirements = { required: ["session_result"] };

	override evaluate(env: Environment): Environment {
		const state = env.getString("session_result", "query_string_params.state");
		if (state == null) {
			throw this.error("state not present in the result from our iframe; this might be a bug in the test.");
		}

		if (state !== CheckSessionResultIsUnchanged.EXPECTED) {
			throw this.error(
				"state from the OP's check_session_iframe does not have the expected value.",
				args("actual", state, "expected", CheckSessionResultIsUnchanged.EXPECTED),
			);
		}

		this.logSuccess(
			"state from the OP's check_session_iframe is '" + CheckSessionResultIsUnchanged.EXPECTED + "' as expected.",
		);

		return env;
	}
}

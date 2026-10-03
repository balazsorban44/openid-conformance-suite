import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckPostLogoutState extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["post_logout_redirect"], strings: ["end_session_state"] };

	override evaluate(env: Environment): Environment {
		const state = env.getString("post_logout_redirect", "query_string_params.state");
		const expectedState = env.getString("end_session_state") as string;
		if (state == null) {
			throw this.error("state not present in query params passed to post logout redirect uri.");
		}

		if (expectedState !== state) {
			throw this.error(
				"state in query params passed to post logout redirect uri does not match state passed in the end_session request.",
				args("actual", state, "expected", expectedState),
			);
		}

		this.logSuccess("state passed to post logout redirect uri matches request");

		return env;
	}
}

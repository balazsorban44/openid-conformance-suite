import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckNoPostLogoutState extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["post_logout_redirect"] };

	override evaluate(env: Environment): Environment {
		const state = env.getString("post_logout_redirect", "query_string_params.state");
		if (state != null) {
			throw this.error(
				"state present in query params passed to post logout redirect uri, but no state was passed to request.",
			);
		}

		this.logSuccess("state not passed to post logout redirect uri.");

		return env;
	}
}

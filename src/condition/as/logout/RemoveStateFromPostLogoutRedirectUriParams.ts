import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class RemoveStateFromPostLogoutRedirectUriParams extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["post_logout_redirect_uri_params"] };
	static override post: EnvironmentRequirements = { required: ["post_logout_redirect_uri_params"] };

	override evaluate(env: Environment): Environment {
		const responseParams = env.getObject("post_logout_redirect_uri_params") as JsonObject;
		if ("state" in responseParams) {
			delete responseParams["state"];
			this.log("Removed state from end_session_endpoint response parameters", args("params", responseParams));
			env.putObject("post_logout_redirect_uri_params", responseParams);
		} else {
			this.log(
				"end_session_endpoint response parameters does not contain a state parameter",
				args("params", responseParams),
			);
		}

		return env;
	}
}

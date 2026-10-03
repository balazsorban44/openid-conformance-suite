import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class AddInvalidStateToPostLogoutRedirectUriParams extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["post_logout_redirect_uri_params"] };
	static override post: EnvironmentRequirements = { required: ["post_logout_redirect_uri_params"] };

	override evaluate(env: Environment): Environment {
		const responseParams = env.getObject("post_logout_redirect_uri_params") as JsonObject;
		if ("state" in responseParams) {
			responseParams["state"] = OIDFJSON.getString(responseParams["state"]) + "_INVALID";
			this.log("Added invalid value for state parameter", args("params", responseParams));
			env.putObject("post_logout_redirect_uri_params", responseParams);
		} else {
			//might be better to throw an error assuming that this condition will be used only when state is required?
			responseParams["state"] = "INVALID";
			this.log("Added invalid value for state parameter", args("params", responseParams));
			env.putObject("post_logout_redirect_uri_params", responseParams);
		}

		return env;
	}
}

import {
	AbstractCondition,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ChangeSubInUserInfoResponseToBeInvalid extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["user_info_endpoint_response"] };
	static override post: EnvironmentRequirements = { required: ["user_info_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const userInfoResponse = env.getObject("user_info_endpoint_response") as JsonObject;
		userInfoResponse["sub"] = OIDFJSON.getString(userInfoResponse["sub"]) + "invalid";
		env.putObject("user_info_endpoint_response", userInfoResponse);

		this.log("Added invalid sub to userinfo endpoint output", userInfoResponse);

		return env;
	}
}

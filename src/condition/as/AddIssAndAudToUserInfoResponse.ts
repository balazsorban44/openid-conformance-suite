import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddIssAndAudToUserInfoResponse extends AbstractCondition {
	/**
	 * Should be used when signing the userinfo response
	 * @param env
	 * @return
	 */
	static override pre: EnvironmentRequirements = { required: ["user_info_endpoint_response", "client"] };
	static override post: EnvironmentRequirements = { required: ["user_info_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const userinfoResponse = env.getObject("user_info_endpoint_response") as JsonObject;
		const clientId = env.getString("client", "client_id");
		const issuer = env.getString("issuer");
		userinfoResponse["iss"] = issuer;
		userinfoResponse["aud"] = clientId;
		env.putObject("user_info_endpoint_response", userinfoResponse);
		this.log("Added iss and aud claims to userinfo response", args("iss", issuer, "aud", clientId));
		return env;
	}
}

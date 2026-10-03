import {
	AbstractCondition,
	args,
	isJsonObject,
	JsonParseException,
	parseJson,
	type Environment,
	type EnvironmentRequirements,
	type JsonValue,
} from "../../framework/index.ts";

export class ExtractUserInfoFromUserInfoEndpointResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["userinfo_endpoint_response_full"] };
	static override post: EnvironmentRequirements = { required: ["userinfo"] };

	override evaluate(env: Environment): Environment {
		env.removeObject("userinfo");

		const userInfoStr = env.getString("userinfo_endpoint_response_full", "body");
		let elt: JsonValue;
		try {
			elt = parseJson(userInfoStr as string);
		} catch (e) {
			if (e instanceof JsonParseException) {
				throw this.error("UserInfo endpoint response is not JSON", e);
			}
			throw e;
		}
		if (!isJsonObject(elt)) {
			// Java: getAsJsonObject() throws IllegalStateException
			throw this.error(
				"UserInfo endpoint response is not a JSON object",
				new Error("Not a JSON Object: " + JSON.stringify(elt)),
			);
		}
		const userInfo = elt;
		env.putObject("userinfo", userInfo);
		this.logSuccess("Extracted user info", args("userinfo", userInfo));
		return env;
	}
}

import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckCallbackHttpMethodIsPost extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["callback_http_method"] };

	override evaluate(env: Environment): Environment {
		const method = env.getString("callback_http_method") as string;

		if (method !== "POST") {
			throw this.error("The HTTP method used at redirect_uri is not 'POST'", args("method", method));
		}

		this.logSuccess("HTTP method used at redirect_uri is 'POST'");
		return env;
	}
}

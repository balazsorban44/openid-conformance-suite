import {
	AbstractCondition,
	args,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Creates a callback URL based on the base_url environment value
 */
export class CreateRandomImplicitSubmitUrl extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { required: ["implicit_submit"] };

	override evaluate(env: Environment): Environment {
		const baseUrl = env.getString("base_url") as string;

		if (baseUrl === "") {
			throw this.error("Base URL is empty");
		}

		// create a random submission URL
		const path = "implicit/" + RandomStringUtils.nextAlphanumeric(20);

		const o: JsonObject = {};
		o["path"] = path;
		o["fullUrl"] = baseUrl + "/" + path;

		env.putObject("implicit_submit", o);

		this.logSuccess("Created random implicit submission URL", args("implicit_submit", o));

		return env;
	}
}

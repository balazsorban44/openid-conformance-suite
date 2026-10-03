import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class SetResourceMethodToPost extends AbstractCondition {
	static override post: EnvironmentRequirements = { required: ["resource"] };

	override evaluate(env: Environment): Environment {
		let resource = env.getObject("resource");
		if (resource == null) {
			resource = {} as JsonObject;
		}
		delete resource["resourceMethod"];
		resource["resourceMethod"] = "POST";
		env.putObject("resource", resource);
		this.logSuccess("Set protected resource access method to POST");

		return env;
	}
}

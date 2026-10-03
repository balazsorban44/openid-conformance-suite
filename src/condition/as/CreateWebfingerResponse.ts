import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateWebfingerResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["incoming_webfinger_request"],
		strings: ["incoming_webfinger_resource"],
	};
	static override post: EnvironmentRequirements = { required: ["webfinger_response"] };

	override evaluate(env: Environment): Environment {
		const response: JsonObject = {};
		response["subject"] = env.getString("incoming_webfinger_resource");
		const linksArray: JsonArray = [];
		const linkEntry: JsonObject = {};
		linkEntry["rel"] = "http://openid.net/specs/connect/1.0/issuer";
		linkEntry["href"] = env.getString("issuer");
		linksArray.push(linkEntry);
		response["links"] = linksArray;

		env.putObject("webfinger_response", response);

		this.log("Created webfinger response", args("webfinger_response", response));

		return env;
	}
}

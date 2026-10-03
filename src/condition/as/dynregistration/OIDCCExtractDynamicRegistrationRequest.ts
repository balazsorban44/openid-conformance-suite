import {
	AbstractCondition,
	args,
	OIDFJSON,
	parseJsonObject,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class OIDCCExtractDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["incoming_request"] };
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const requestBody = OIDFJSON.getString((env.getObject("incoming_request") as JsonObject)["body"]);
		const requestJson = parseJsonObject(requestBody);
		env.putObject("dynamic_registration_request", requestJson);
		this.logSuccess("Extracted dynamic client registration request", args("request", requestJson));
		return env;
	}
}

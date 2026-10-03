import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddClientAssertionToRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["request_form_parameters"],
		strings: ["client_assertion"],
	};
	static override post: EnvironmentRequirements = { required: ["request_form_parameters"] };

	override evaluate(env: Environment): Environment {
		const o = env.getObject("request_form_parameters") as JsonObject;

		o["client_assertion"] = env.getString("client_assertion");
		o["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

		this.log("Added client assertion", o);

		return env;
	}
}

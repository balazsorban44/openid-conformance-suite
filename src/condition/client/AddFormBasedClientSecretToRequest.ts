import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddFormBasedClientSecretToRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["request_form_parameters", "client"] };
	static override post: EnvironmentRequirements = { required: ["request_form_parameters"] };

	override evaluate(env: Environment): Environment {
		const o = env.getObject("request_form_parameters") as JsonObject;

		o["client_id"] = env.getString("client", "client_id");
		o["client_secret"] = env.getString("client", "client_secret");

		this.log(o);

		return env;
	}
}

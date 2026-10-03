import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddClientIdToRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["request_form_parameters", "client"] };
	static override post: EnvironmentRequirements = { required: ["request_form_parameters"] };

	override evaluate(env: Environment): Environment {
		const o = env.getObject("request_form_parameters") as JsonObject;

		const clientId = env.getString("client", "client_id");
		if (!clientId) {
			throw this.error("client_id is null or empty");
		}

		o["client_id"] = clientId;

		this.log(o);

		return env;
	}
}

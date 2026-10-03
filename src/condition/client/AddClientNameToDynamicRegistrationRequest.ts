import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddClientNameToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"] };
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		// get the specified "client_name" from the client object if there is one.
		let clientName = env.getString("client_name");

		if (!clientName) {
			clientName = "OIDF Conformance Test " + this.getTestId();
		} else {
			clientName = clientName + " " + this.getTestId();
		}

		dynamicRegistrationRequest["client_name"] = clientName;

		this.log("Added client_name to registration request", dynamicRegistrationRequest);

		return env;
	}
}

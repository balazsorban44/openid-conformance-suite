import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../../framework/index.ts";

export class SetClientGrantTypesToAuthorizationCodeOnly extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;
		const grantTypes: JsonArray = [];
		grantTypes.push("authorization_code");
		client["grant_types"] = grantTypes;
		env.putObject("client", client);
		this.log("Set grant_types to ['authorization_code'] for the registered client", args("client", client));
		return env;
	}
}

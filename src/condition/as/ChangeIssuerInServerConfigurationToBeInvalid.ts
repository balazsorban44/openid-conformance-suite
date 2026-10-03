import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ChangeIssuerInServerConfigurationToBeInvalid extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };
	static override post: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const server = env.getObject("server") as JsonObject;

		const currentIssuer = OIDFJSON.getString(server["issuer"]);
		const newIssuer = currentIssuer + "INVALID";
		server["issuer"] = newIssuer;
		env.putObject("server", server);
		this.log("Added invalid issuer to server configuration", args("issuer", newIssuer));

		return env;
	}
}

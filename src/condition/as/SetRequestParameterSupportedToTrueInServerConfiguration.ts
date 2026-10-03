import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class SetRequestParameterSupportedToTrueInServerConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };
	static override post: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const server = env.getObject("server") as JsonObject;

		this.addSupported(server);

		this.log(this.getLogMessage(), args("server", server));

		return env;
	}

	protected addSupported(server: JsonObject): void {
		server["request_parameter_supported"] = true;
	}

	protected getLogMessage(): string {
		return "Enabled request parameter support in server configuration";
	}
}

import { AbstractCondition, args, type Environment, type JsonObject } from "../../framework/index.ts";

export abstract class AbstractSetScopeInClientConfiguration extends AbstractCondition {
	protected setScopeInClientConfiguration(env: Environment, scope: string, additionalLogMsg = ""): Environment {
		const client = env.getObject("client") as JsonObject;
		client["scope"] = scope;
		env.putObject("client", client);
		this.log(`Set scope in client configuration to "${scope}"` + additionalLogMsg, args("scope", scope));
		return env;
	}
}

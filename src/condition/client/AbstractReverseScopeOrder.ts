import { AbstractCondition, args, OIDFJSON, type Environment, type JsonObject } from "../../framework/index.ts";

export abstract class AbstractReverseScopeOrder extends AbstractCondition {
	protected reverseScope(env: Environment, envKey: string): void {
		const authorizationEndpointRequest = env.getObject(envKey) as JsonObject;

		const jsonScope = authorizationEndpointRequest["scope"];
		if (jsonScope == null || jsonScope === "") {
			throw this.error("no scope found");
		}
		const scope = OIDFJSON.getString(jsonScope);

		// Java's String.split drops trailing empty strings, JS keeps them
		const scopes = scope.split(" ");
		while (scopes.length > 0 && scopes[scopes.length - 1] === "") {
			scopes.pop();
		}
		if (scopes.length < 2) {
			throw this.error("'scope' in the configuration must contain more than one scope to run this test");
		}

		scopes.reverse();

		const newScope = scopes.join(" ");

		authorizationEndpointRequest["scope"] = newScope;

		this.log("Reversed order of scopes in " + envKey, args("original", scope, "reversed", newScope));
	}
}

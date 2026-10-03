import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureOpenIDInScopeRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["scope"] };

	override evaluate(env: Environment): Environment {
		const scope = env.getString("scope") as string;

		const scopes = scope.split(" ");

		if (scopes.includes("openid")) {
			this.logSuccess("Found 'openid' scope in request", args("expected", "openid", "actual", scopes));
			return env;
		} else {
			throw this.error("Coudln't find 'openid' scope in request", args("expected", "openid", "actual", scopes));
		}
	}
}

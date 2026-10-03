import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureScopeContainsAtLeastOneOfProfileEmailPhoneAddress extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["scope"] };

	override evaluate(env: Environment): Environment {
		const scope = env.getString("scope") as string;
		const scopes = scope.split(" ");

		if (scopes.includes("profile") || scopes.includes("email") || scopes.includes("phone") || scopes.includes("address")) {
			this.logSuccess(
				"Found at least one of profile, email, phone and address " + "scopes in request",
				args("actual", scopes),
			);
			return env;
		} else {
			throw this.error(
				"Could not find at least one of profile, email, phone and address scope in request",
				args("actual", scopes),
			);
		}
	}
}

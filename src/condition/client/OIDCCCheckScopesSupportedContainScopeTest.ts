import {
	AbstractCondition,
	args,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class OIDCCCheckScopesSupportedContainScopeTest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server", "client"] };

	override evaluate(env: Environment): Environment {
		const scopesSupported = env.getElementFromObject("server", "scopes_supported");
		const expectedScopeStr = env.getString("client", "scope");
		let errorMessage: string | null = null;

		if (scopesSupported == null) {
			errorMessage = "'scopes_support' is missing from discovery document";
		} else if (!isJsonArray(scopesSupported)) {
			errorMessage = "'scopes_support' in discovery document is not a array";
		} else {
			// convert JsonArray scopesSupported to list string
			const scopesSupportedList: string[] = [];
			for (const scope of scopesSupported) {
				scopesSupportedList.push(OIDFJSON.getString(scope));
			}

			const expectedScopes = (expectedScopeStr as string).split(" ");
			for (const expectedScope of expectedScopes) {
				if (!scopesSupportedList.includes(expectedScope)) {
					errorMessage = "'scopes_support' in discovery document doesn't contain expected scopes";
				}
			}
		}

		if (errorMessage != null) {
			// skip test when scopes is not supported
			env.putBoolean("scopes_not_supported_flag", true);
			throw this.error(errorMessage, args("expected", expectedScopeStr, "actual", scopesSupported));
		}

		this.logSuccess(
			"'scopes_supported' in discovery document contain expected scopes",
			args("expected", expectedScopeStr, "actual", scopesSupported),
		);

		return env;
	}
}

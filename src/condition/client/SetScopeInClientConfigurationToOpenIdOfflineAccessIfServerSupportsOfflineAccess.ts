import { args, isJsonArray, OIDFJSON, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractSetScopeInClientConfiguration } from "./AbstractSetScopeInClientConfiguration.ts";

export class SetScopeInClientConfigurationToOpenIdOfflineAccessIfServerSupportsOfflineAccess extends AbstractSetScopeInClientConfiguration {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const scopesSupported = env.getElementFromObject("server", "scopes_supported");
		if (scopesSupported === undefined) {
			this.log(
				"scopes_supported is not present in the discovery document, so assuming server does not support 'offline_access' scope and hence not adding it to the list of scopes to be requested",
			);
			return env;
		}

		if (!isJsonArray(scopesSupported)) {
			throw this.error("'scopes_supported' is not a array");
		}

		// convert JsonArray scopesSupported to list string
		const scopesSupportedList: string[] = [];
		for (const scope of scopesSupported) {
			scopesSupportedList.push(OIDFJSON.getString(scope));
		}

		if (!scopesSupportedList.includes("offline_access")) {
			this.log(
				"scopes supported does not contain 'offline_access' so not adding it to the list of scopes to be requested",
				args("scopes_supported", scopesSupportedList),
			);
			return env;
		}

		return this.setScopeInClientConfiguration(
			env,
			"openid offline_access",
			"as 'scope_supported' contains 'offline_access'",
		);
	}
}

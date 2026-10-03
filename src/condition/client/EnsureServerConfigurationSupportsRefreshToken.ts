import {
	AbstractCondition,
	args,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
} from "../../framework/index.ts";

export class EnsureServerConfigurationSupportsRefreshToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const supportedGrantTypesElement = env.getElementFromObject("server", "grant_types_supported");
		if (supportedGrantTypesElement == null) {
			// Null implies default ["authorization_code", "implicit"]
			throw this.error(
				"The server issued a refresh token but does not claim to support this grant type (grant_types_supported in not present in the discovery document)",
			);
		}

		let supportedGrantTypes: JsonArray;
		if (isJsonArray(supportedGrantTypesElement)) {
			supportedGrantTypes = supportedGrantTypesElement;
		} else {
			throw this.error("supported_grant_types is present in the discovery document but is not an array");
		}

		for (const grantType of supportedGrantTypes) {
			if (OIDFJSON.getString(grantType) === "refresh_token") {
				this.logSuccess(
					"The server configuration indicates support for refresh tokens",
					args("supported_grant_types", supportedGrantTypes),
				);
				return env;
			}
		}

		throw this.error(
			"The server issued a refresh token but does not claim to support this grant type",
			args("supported_grant_types", supportedGrantTypes),
		);
	}
}

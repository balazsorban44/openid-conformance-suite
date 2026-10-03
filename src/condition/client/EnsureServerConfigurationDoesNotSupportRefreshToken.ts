import {
	AbstractCondition,
	args,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
} from "../../framework/index.ts";

export class EnsureServerConfigurationDoesNotSupportRefreshToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const supportedGrantTypesElement = env.getElementFromObject("server", "grant_types_supported");
		if (supportedGrantTypesElement == null) {
			// Null implies default ["authorization_code", "implicit"]
			this.logSuccess(
				"The server did not issue a refresh token and does not claim to support this grant type (grant_types_supported in not present in the discovery document)",
			);
			return env;
		}

		let supportedGrantTypes: JsonArray;
		if (isJsonArray(supportedGrantTypesElement)) {
			supportedGrantTypes = supportedGrantTypesElement;
		} else {
			throw this.error("supported_grant_types is present in the discovery document but is not an array");
		}

		for (const grantType of supportedGrantTypes) {
			if (OIDFJSON.getString(grantType) === "refresh_token") {
				throw this.error(
					"The server supports refresh tokens, but did not issue one. This is acceptable if the server has a policy of issuing refresh tokens to some clients, but not to openid clients.",
					args("supported_grant_types", supportedGrantTypes),
				);
			}
		}

		this.logSuccess(
			"The server did not issue a refresh token, and does not claim to support this grant type",
			args("supported_grant_types", supportedGrantTypes),
		);

		return env;
	}
}

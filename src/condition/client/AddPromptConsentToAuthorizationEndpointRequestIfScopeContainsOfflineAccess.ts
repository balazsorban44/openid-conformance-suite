import {
	AbstractCondition,
	OIDFJSON,
	has,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	/**
	 * Adds prompt=consent to authorization request only when scope contains offline_access
	 * @param env
	 * @return
	 */
	override evaluate(env: Environment): Environment {
		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;
		if (!has(authorizationEndpointRequest, "scope")) {
			this.logSuccess("Not adding prompt=consent as the authorization endpoint request does not contain a scope");
			return env;
		}
		const scope = OIDFJSON.getString(authorizationEndpointRequest["scope"]);
		if (!scope.includes("offline_access")) {
			this.logSuccess("Not adding prompt=consent as the scope in the configuration does not contain offline_access");
			return env;
		}
		authorizationEndpointRequest["prompt"] = "consent";
		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);
		this.logSuccess("Added prompt=consent to authorization endpoint request", authorizationEndpointRequest);
		return env;
	}
}

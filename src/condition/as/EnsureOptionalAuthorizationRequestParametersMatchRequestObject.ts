import {
	AbstractCondition,
	args,
	has,
	jsonEquals,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { EnsureRequiredAuthorizationRequestParametersMatchRequestObject } from "./EnsureRequiredAuthorizationRequestParametersMatchRequestObject.ts";

/**
 * Use this condition for logging a WARNING only
 * Normally this condition should never lead to a failure
 */
export class EnsureOptionalAuthorizationRequestParametersMatchRequestObject extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_endpoint_http_request_params", "authorization_request_object"],
	};

	override evaluate(env: Environment): Environment {
		//we loop over all parameters and add a log entry if they are not equal
		const authzEndpointReqParams = env.getObject("authorization_endpoint_http_request_params") as JsonObject;
		const requestObjectClaims = env.getElementFromObject("authorization_request_object", "claims") as JsonObject;

		const argsForLog: Record<string, unknown> = {};

		for (const paramName of Object.keys(authzEndpointReqParams)) {
			if (EnsureRequiredAuthorizationRequestParametersMatchRequestObject.parametersThatMustMatch.has(paramName)) {
				//these should be already checked. checking again would cause duplicate logs
				continue;
			}
			if (has(requestObjectClaims, paramName)) {
				//scope=openid special case. We don't log a warning when scope http request parameter equals openid,
				//only when it is exactly "openid".
				//We will log a warning when it is "openid xyz" in http request but "openid xyz abc" in request object
				if ("scope" === paramName) {
					const scopeValue = OIDFJSON.getString(authzEndpointReqParams[paramName]);
					if ("openid" === scopeValue) {
						continue;
					}
				}
				if (!jsonEquals(authzEndpointReqParams[paramName], requestObjectClaims[paramName])) {
					argsForLog[paramName] = args(
						"Value in http request",
						authzEndpointReqParams[paramName],
						"Value in request object",
						requestObjectClaims[paramName],
					);
				}
			}
		}

		if (Object.keys(argsForLog).length === 0) {
			this.logSuccess("All http request parameters and request object claims match");
			return env;
		}
		throw this.error(
			"Some http request parameters and request object claims do not match. " +
				"This is allowed but you should check if the differences are intentional",
			argsForLog,
		);
	}
}

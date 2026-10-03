import {
	AbstractCondition,
	args,
	jsonEquals,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

/**
 * OIDCC 6.1 and 6.2 say:
 * So that the request is a valid OAuth 2.0 Authorization Request,
 * values for the response_type and client_id parameters MUST be included using the OAuth 2.0 request syntax,
 * since they are REQUIRED by OAuth 2.0.
 * The values for these parameters MUST match those in the Request Object, if present.
 *
 * scope does not need to match:
 * Even if a scope parameter is present in the Request Object value, a scope parameter
 * MUST always be passed using the OAuth 2.0 request syntax containing the openid scope
 * value to indicate to the underlying OAuth 2.0 logic that this is an OpenID Connect request.
 */
export class EnsureRequiredAuthorizationRequestParametersMatchRequestObject extends AbstractCondition {
	static readonly parametersThatMustMatch: Set<string> = new Set(["response_type", "client_id"]);

	static override pre: EnvironmentRequirements = {
		required: ["authorization_endpoint_http_request_params", "authorization_request_object"],
	};

	getParametersThatMustMatch(): Set<string> {
		return EnsureRequiredAuthorizationRequestParametersMatchRequestObject.parametersThatMustMatch;
	}

	override evaluate(env: Environment): Environment {
		const failureLogArgs: Record<string, unknown> = {};
		const successLogArgs: Record<string, unknown> = {};

		for (const paramName of this.getParametersThatMustMatch()) {
			const valueFromHttpRequest = env.getElementFromObject("authorization_endpoint_http_request_params", paramName);
			const valueFromRequestObject = env.getElementFromObject("authorization_request_object", "claims." + paramName);
			if (valueFromHttpRequest === undefined) {
				//this is unlikely to happen as probably another condition will fail before this one
				//when one of these parameters are missing but just in case
				failureLogArgs[paramName] = `Required parameter '${paramName}' was not found in http request parameters`;
			} else {
				if (valueFromRequestObject !== undefined) {
					if (!jsonEquals(valueFromHttpRequest, valueFromRequestObject)) {
						const paramValuesMapForLog = args(
							"Value in http request",
							valueFromHttpRequest,
							"Value in request object",
							valueFromRequestObject,
						);
						failureLogArgs[paramName] = paramValuesMapForLog;
					} else {
						successLogArgs[paramName] = valueFromHttpRequest;
					}
				} else {
					successLogArgs[paramName] = "Not found in request object";
				}
			}
		}

		if (Object.keys(failureLogArgs).length === 0) {
			this.logSuccess("Required http request parameters match request object claims", successLogArgs);
			return env;
		}

		throw this.error("Required http request parameters and request object claims must match", failureLogArgs);
	}
}

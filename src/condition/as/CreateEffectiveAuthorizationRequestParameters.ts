import {
	AbstractCondition,
	args,
	deepCopy,
	has,
	JsonParseException,
	OIDFJSON,
	parseJson,
	UnexpectedJsonTypeException,
	ValueIsJsonNullException,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { EnsureNumericRequestObjectClaimsAreNotNull } from "./EnsureNumericRequestObjectClaimsAreNotNull.ts";

/**
 * Merges http request parameters and request object parameters
 * and creates effective_authorization_endpoint_request environment entry
 */
export class CreateEffectiveAuthorizationRequestParameters extends AbstractCondition {
	static readonly ENV_KEY = "effective_authorization_endpoint_request";

	//always use these constants to get values. just in case the keys, JsonObject structure change etc
	static readonly MAX_AGE = "max_age";
	static readonly PROMPT = "prompt";
	static readonly STATE = "state";
	static readonly REDIRECT_URI = "redirect_uri";
	static readonly RESPONSE_TYPE = "response_type";
	static readonly CLIENT_ID = "client_id";
	static readonly SCOPE = "scope";
	static readonly NONCE = "nonce";
	static readonly CODE_CHALLENGE = "code_challenge";
	static readonly CODE_CHALLENGE_METHOD = "code_challenge_method";
	static readonly DPOP_JKT = "dpop_jkt";

	//WARNING "authorization_request_object" is also used but it's not required
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_http_request_params"] };
	static override post: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		return this.createEffectiveAuthorizationRequestParameters(env);
	}

	protected customizeEffectiveAuthorizationRequestParams(_env: Environment, _jsonObject: JsonObject): void {}

	protected createEffectiveAuthorizationRequestParameters(env: Environment): Environment {
		const authzEndpointReqParams = env.getObject("authorization_endpoint_http_request_params") as JsonObject;
		const effective = deepCopy(authzEndpointReqParams);
		delete effective["request_uri"];

		this.customizeEffectiveAuthorizationRequestParams(env, effective);

		this.convertJsonStringParam(effective, "authorization_details");
		this.convertJsonStringParam(effective, "dcql_query");
		this.convertJsonStringParam(effective, "client_metadata");

		// Normalize numeric HTTP query params (e.g. max_age arrives as string "99" from URL).
		// This runs BEFORE the request object merge so that request object types are preserved —
		// a request object that sends max_age as a string is a protocol violation that should be
		// caught by a downstream condition, not silently normalized here.
		for (const claimName of EnsureNumericRequestObjectClaimsAreNotNull.numericClaimNames) {
			if (has(effective, claimName)) {
				const claimJsonElement = effective[claimName];
				try {
					const claimAsNumber = OIDFJSON.forceConversionToNumber(claimJsonElement);
					effective[claimName] = claimAsNumber;
				} catch (ex) {
					if (ex instanceof ValueIsJsonNullException || ex instanceof UnexpectedJsonTypeException) {
						// leave as-is; will be handled after request object merge
					} else {
						throw ex;
					}
				}
			}
		}

		//override request parameters if authorization_request_object exists
		if (env.containsObject("authorization_request_object")) {
			const requestObjectClaims = env.getElementFromObject("authorization_request_object", "claims") as JsonObject;

			for (const paramName of Object.keys(requestObjectClaims)) {
				effective[paramName] = requestObjectClaims[paramName];
			}
		}

		env.putObject(CreateEffectiveAuthorizationRequestParameters.ENV_KEY, effective);
		this.logSuccess(
			"Merged http request parameters with request object claims",
			args(CreateEffectiveAuthorizationRequestParameters.ENV_KEY, effective),
		);
		return env;
	}

	/**
	 * When parameters like dcql_query, client_metadata, or authorization_details are passed as URL query
	 * params (URL_QUERY request method), they arrive as JSON-serialized strings. Parse them back into
	 * JSON so downstream conditions can work with them the same way as when they come from a signed
	 * request object (JAR).
	 */
	protected convertJsonStringParam(params: JsonObject, paramName: string): void {
		if (!has(params, paramName)) {
			return;
		}
		const el = params[paramName];
		if (typeof el !== "string") {
			return; // already a JSON object/array, nothing to do
		}
		const jsonString = OIDFJSON.getString(el);
		try {
			const parsed = parseJson(jsonString);
			params[paramName] = parsed;
		} catch (e) {
			if (e instanceof JsonParseException) {
				throw this.error("Unable to parse " + paramName + " as JSON", e, args(paramName, jsonString));
			}
			throw e;
		}
	}
}

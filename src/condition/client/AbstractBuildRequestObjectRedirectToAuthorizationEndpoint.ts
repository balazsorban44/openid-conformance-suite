import {
	AbstractCondition,
	args,
	isJsonPrimitive,
	OIDFJSON,
	type Environment,
	type JsonObject,
} from "../../framework/index.ts";

export abstract class AbstractBuildRequestObjectRedirectToAuthorizationEndpoint extends AbstractCondition {
	/**
	 * A list of parameters that must also be included in the url query, even when they are already in the request
	 * object.
	 *
	 * response_type, client_id, scope are required by these clauses from
	 * https://openid.net/specs/openid-connect-core-1_0.html#RequestObject :
	 *
	 *    So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and client_id
	 *    parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by OAuth 2.0. The
	 *    values for these parameters MUST match those in the Request Object, if present.
	 *
	 *    Even if a scope parameter is present in the Request Object value, a scope parameter MUST always be passed
	 *    using the OAuth 2.0 request syntax containing the openid scope value to indicate to the underlying OAuth
	 *    2.0 logic that this is an OpenID Connect request.
	 *
	 * redirect_uri is required because of this clause from https://tools.ietf.org/html/rfc6749#section-3.1.2.3 :
	 *
	 *    If multiple redirection URIs have been registered, if only part of
	 *    the redirection URI has been registered, or if no redirection URI has
	 *    been registered, the client MUST include a redirection URI with the
	 *    authorization request using the "redirect_uri" request parameter.
	 */
	private static readonly REQUIRED_DUPLICATES = ["response_type", "client_id", "scope", "redirect_uri"];

	/**
	 * @param includeDuplicates If true include the duplicate parameters required by RFC6749/OIDC - if false,
	 *                          skip the duplicates as permitted by JAR / PAR.
	 * @param reverseParameterOrder If true, sort query parameters in reverse alphabetical order to test that
	 *                              implementations handle different parameter orderings.
	 */
	protected buildRedirect(
		env: Environment,
		paramName: string,
		paramValue: string | null,
		includeDuplicates: boolean,
		reverseParameterOrder: boolean,
	): Environment {
		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;
		const requestObjectClaims = env.getObject("request_object_claims") as JsonObject;

		const authorizationEndpoint =
			env.getString("authorization_endpoint") != null
				? env.getString("authorization_endpoint")
				: env.getString("server", "authorization_endpoint");
		if (!authorizationEndpoint) {
			throw this.error("Couldn't find authorization endpoint");
		}

		// Java: TreeMap with natural (or reverse) String ordering - Strings compare by UTF-16 code units, as in JS
		const params = new Map<string, string | null>();

		params.set(paramName, paramValue);

		for (const key of Object.keys(authorizationEndpointRequest)) {
			const requestObjectElement = requestObjectClaims[key];
			const requestParameterElement = authorizationEndpointRequest[key];
			if (
				(requestObjectElement !== undefined && !isJsonPrimitive(requestObjectElement)) ||
				!isJsonPrimitive(requestParameterElement)
			) {
				// only handle stringable values for now (as BuildPlainRedirectToAuthorizationEndpoint)
				continue;
			}

			let requestObjectValue: string | null = null;
			if (requestObjectElement !== undefined) {
				requestObjectValue = OIDFJSON.forceConversionToString(requestObjectElement);
			}
			const requestParameterValue = OIDFJSON.forceConversionToString(requestParameterElement);

			if (key === "state") {
				const exposeState = env.getBoolean("expose_state_in_authorization_endpoint_request");
				if (exposeState != null && exposeState === true) {
					params.set("state", env.getString("state"));
				}
			}

			if (includeDuplicates) {
				if (
					AbstractBuildRequestObjectRedirectToAuthorizationEndpoint.REQUIRED_DUPLICATES.includes(key) ||
					requestObjectValue == null ||
					requestParameterValue !== requestObjectValue
				) {
					params.set(key, requestParameterValue);
				}
			} else {
				if (key === "client_id") {
					params.set(key, requestParameterValue);
				}
			}
		}

		const sortedKeys = [...params.keys()].toSorted((a, b) => {
			const order = a < b ? -1 : a > b ? 1 : 0;
			return reverseParameterOrder ? -order : order;
		});

		// UPSTREAM: Spring's UriComponentsBuilder.toUriString() percent-encodes less than URLSearchParams does (e.g.
		// it leaves ':' '/' and '+' alone and encodes a space as %20); the parameters are equivalent once decoded.
		const builder = new URL(authorizationEndpoint);
		for (const key of sortedKeys) {
			// a null value (e.g. a missing state) is added as a parameter without a value by Spring
			builder.searchParams.append(key, params.get(key) ?? "");
		}

		const redirectTo = builder.toString();

		this.logSuccess("Sending to authorization endpoint", args("redirect_to_authorization_endpoint", redirectTo));

		env.putString("redirect_to_authorization_endpoint", redirectTo);

		return env;
	}
}

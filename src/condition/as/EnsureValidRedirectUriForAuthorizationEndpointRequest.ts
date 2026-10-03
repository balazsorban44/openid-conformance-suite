import {
	AbstractCondition,
	args,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";
import { RedirectURIValidationUtil } from "../../util/validation/RedirectURIValidationUtil.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

/**
 * Checks if the requested redirect_uri is ONE of the redirect_uris
 * and has the correct scheme
 *
 * also note 7.3.  Self-Issued OpenID Provider Request
 * ...Since the Client's redirect_uri URI value is communicated as the Client ID, a redirect_uri parameter is
 * NOT REQUIRED to also be included in the request...
 */
export class EnsureValidRedirectUriForAuthorizationEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["client", CreateEffectiveAuthorizationRequestParameters.ENV_KEY],
	};
	static override post: EnvironmentRequirements = { strings: ["authorization_endpoint_request_redirect_uri"] };

	override evaluate(env: Environment): Environment {
		const redirectUrisElement = env.getElementFromObject("client", "redirect_uris");
		if (redirectUrisElement === undefined) {
			throw this.error("redirect_uris is undefined for the client");
		}

		const actual = env.getString(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.REDIRECT_URI,
		);
		if (actual == null) {
			throw this.error(
				"redirect_uri is not present in authorization request",
				args("auth_request", env.getObject(CreateEffectiveAuthorizationRequestParameters.ENV_KEY)),
			);
		}

		// UPSTREAM: java.net.URI is replaced by the WHATWG URL parser for the syntax check (java.net.URI also
		// accepts relative references, URL does not); a '#' in a syntactically valid URI always starts the fragment.
		if (!URL.canParse(actual)) {
			throw this.error("Invalid redirect_uri", args("redirect_uri", actual));
		}
		if (actual.includes("#")) {
			throw this.error(
				"Invalid redirect_uri. redirect_uri includes a fragment component.",
				args("redirect_uri", actual),
			);
		}

		if (!isJsonArray(redirectUrisElement)) {
			// Java: getAsJsonArray() throws IllegalStateException
			throw this.error(
				"redirect_uris is not an array",
				new Error("Not a JSON Array: " + JSON.stringify(redirectUrisElement)),
			);
		}
		const redirectUris = redirectUrisElement;
		for (const e of redirectUris) {
			const uri = OIDFJSON.getString(e);
			if (actual === uri) {
				//require https if application_type is web and response_type is not equal to code
				const applicationType = env.getString("client", "application_type");
				const responseType = env.getString(
					CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
					CreateEffectiveAuthorizationRequestParameters.RESPONSE_TYPE,
				);
				if (!RedirectURIValidationUtil.requireHttpsIfWebAndResponseTypeNotCode(applicationType, responseType, actual)) {
					throw this.error(
						"redirect_uri is one of the registered uris but uses http scheme which " +
							"is not allowed when application_type is web and response type is not code",
						args("actual", actual, "expected", redirectUris),
					);
				}
				let allowed: boolean;
				try {
					allowed = RedirectURIValidationUtil.dontAllowHttpIfNativeAndNotLocalhost(applicationType, actual);
				} catch (uriSyntaxException) {
					throw this.error("Invalid redirect_uri syntax", uriSyntaxException, args("actual", actual));
				}
				if (!allowed) {
					throw this.error(
						"redirect_uri is one of the registered uris but http scheme  " +
							" is only allowed for localhost for native applications",
						args("actual", actual, "expected", redirectUris),
					);
				}
				this.logSuccess(
					"redirect_uri is one of the allowed redirect uris",
					args("actual", actual, "expected", redirectUris),
				);
				env.putString("authorization_endpoint_request_redirect_uri", actual);
				return env;
			}
		}
		throw this.error("redirect_uri is not one of the allowed ones", args("actual", actual, "expected", redirectUris));
	}
}

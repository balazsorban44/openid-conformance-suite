import {
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../../framework/index.ts";
import { parseJavaURI, URISyntaxException } from "../../../util/jdk/uri.ts";
import { RedirectURIValidationUtil } from "../../../util/validation/RedirectURIValidationUtil.ts";
import { AbstractClientValidationCondition, IllegalStateException } from "./AbstractClientValidationCondition.ts";

/**
 * Registration request must contain at least one redirect_uri
 *
 * These checks apply to authorization request validation as well
 */
export class OIDCCValidateClientRedirectUris extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;

		let validUriCount = 0;
		let redirectUriString: string | null = null;
		let redirectUrisArray: JsonArray | null = null;
		try {
			redirectUrisArray = this.getRedirectUris();
			if (redirectUrisArray == null) {
				throw this.error("redirect_uris is not set");
			}
		} catch (ex) {
			if (!(ex instanceof IllegalStateException)) {
				throw ex;
			}
			throw this.error("redirect_uris is not encoded as an array", ex);
		}

		for (let i = 0; i < redirectUrisArray.length; i++) {
			try {
				redirectUriString = OIDFJSON.getString(redirectUrisArray[i]);
				const uri = parseJavaURI(redirectUriString);
				if (uri.fragment != null) {
					this.appendError(
						"failure_reason",
						"Invalid redirect uri. URI includes a fragment component.",
						"details",
						args("invalid_uri", redirectUriString),
					);
					continue;
				}
				//Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris;
				//they MUST NOT use localhost as the hostname
				if (this.isApplicationTypeWeb() && this.hasImplicitResponseTypes()) {
					if ("http" === uri.scheme?.toLowerCase()) {
						this.appendError(
							"failure_reason",
							"Web Clients using the OAuth Implicit Grant Type MUST " +
								"only register URLs using the https scheme as redirect_uris",
							"details",
							args("uri", redirectUriString),
						);
						continue;
					}
					//they MUST NOT use localhost as the hostname
					// UPSTREAM: Java throws a NullPointerException when the URI has no (server-based) host
					if (RedirectURIValidationUtil.isLocalhost(uri.host as string)) {
						this.appendError(
							"failure_reason",
							"Web Clients using the OAuth Implicit Grant " + "Type MUST not use localhost as the hostname",
							"details",
							args("uri", redirectUriString, "host", uri.host),
						);
						continue;
					}
				}
				if (this.isApplicationTypeNative() && "http" === uri.scheme?.toLowerCase()) {
					if (!RedirectURIValidationUtil.isLocalhost(uri.host as string)) {
						//Authorization Servers MAY reject Redirection URI values using the http scheme,
						//other than the localhost case for Native Clients.
						//Note: python suite allows http when application type is native and hostname is localhost
						this.appendError(
							"failure_reason",
							"http scheme is allowed only for native applications using localhost",
							"details",
							args("uri", redirectUriString),
						);
						continue;
					}
				}
				validUriCount++;
			} catch (e) {
				if (!(e instanceof URISyntaxException)) {
					throw e;
				}
				this.appendError(
					"failure_reason",
					"Invalid redirect uri: " + e.message,
					"details",
					args("invalid_uri", redirectUriString),
				);
			}
		}
		if (this.validationErrors.length > 0) {
			throw this.error("redirect_uris validation failed", args("errors", this.validationErrors));
		}
		if (validUriCount === 0) {
			throw this.error("At least one redirect_uri is required in dynamic client registration requests.");
		}
		this.logSuccess("Valid redirect_uri(s) provided in registration request", args("redirect_uris", redirectUrisArray));
		return env;
	}
}

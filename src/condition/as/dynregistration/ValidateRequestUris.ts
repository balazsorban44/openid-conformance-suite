import {
	args,
	OIDFJSON,
	UnexpectedJsonTypeException,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { parseJavaURI, URISyntaxException } from "../../../util/jdk/uri.ts";
import { AbstractClientValidationCondition, IllegalStateException } from "./AbstractClientValidationCondition.ts";

/**
 * request_uris
 * OPTIONAL. Array of request_uri values that are pre-registered by the RP for use at the OP.
 * Servers MAY cache the contents of the files referenced by these URIs and not retrieve them
 * at the time they are used in a request. OPs can require that request_uri values used be
 * pre-registered with the require_request_uri_registration discovery parameter.
 * If the contents of the request file could ever change, these URI values SHOULD include the
 * base64url encoded SHA-256 hash value of the file contents referenced by the URI as the value
 * of the URI fragment. If the fragment value used for a URI changes, that signals the server
 * that its cached value for that URI with the old fragment value is no longer valid.
 *
 */
export class ValidateRequestUris extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;
		try {
			const requestUris = this.getRequestUris();
			if (requestUris == null) {
				this.logSuccess("request_uris is not set");
				return env;
			}

			for (const element of requestUris) {
				try {
					const uriString = OIDFJSON.getString(element);
					parseJavaURI(uriString);
				} catch (e) {
					if (e instanceof UnexpectedJsonTypeException) {
						throw this.error("request_uris contains a value that is not encoded as a string", args("element", element));
					}
					if (e instanceof URISyntaxException) {
						throw this.error("request_uris contains a value that is not a valid URI", args("element", element));
					}
					throw e;
				}
			}
			this.logSuccess("request_uris is valid", args("request_uris", requestUris));
			return env;
		} catch (ex) {
			if (!(ex instanceof IllegalStateException)) {
				throw ex;
			}
			throw this.error(
				"request_uris is not encoded as a json array",
				args("request_uris", this.client["request_uris"]),
			);
		}
	}
}

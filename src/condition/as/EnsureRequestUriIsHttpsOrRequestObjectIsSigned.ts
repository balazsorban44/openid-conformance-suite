import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

/**
 * OIDCC 6.2:
 *   The contents of the resource referenced by the URL MUST be a Request Object.
 *   The scheme used in the request_uri value MUST be https, unless the target
 *   Request Object is signed in a way that is verifiable by the Authorization Server.
 *
 * We first fetch the request object from request_uri even if it's not https
 * but we throw an error if request object is not signed and request_uri was not https
 */
export class EnsureRequestUriIsHttpsOrRequestObjectIsSigned extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_request_object", "authorization_endpoint_http_request_params"],
	};

	override evaluate(env: Environment): Environment {
		const requestUri = env.getString("authorization_endpoint_http_request_params", "request_uri") as string;
		const alg = env.getString("authorization_request_object", "header.alg");

		if (requestUri.toLowerCase().startsWith("https://")) {
			this.logSuccess("request_uri is a https url", args("request_uri", requestUri));
			return env;
		} else {
			//OIDCC-6.1:
			//   The Request Object MAY be signed or unsigned (plaintext). When it is plaintext,
			//   this is indicated by use of the none algorithm [JWA] in the JOSE Header.
			if ("none" !== alg) {
				this.logSuccess(
					"request_uri is not a https url but the request object is signed",
					args("request_uri", requestUri, "alg", alg),
				);
				return env;
			} else {
				throw this.error(
					"The scheme used in the request_uri value MUST be https, as the target Request Object is not signed",
					args("request_uri", requestUri, "alg", alg),
				);
			}
		}
	}
}

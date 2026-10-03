import { AbstractCondition, type Environment } from "../../framework/index.ts";

export class ExpectRedirectUriHasBeenCalled extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		const authorizationEndpointResponse = env.getObject("authorization_endpoint_response");
		if (authorizationEndpointResponse == null) {
			throw this.error(
				"The OpenID Connect core specification states that 'Authorization Servers MUST support the use " +
					"of the HTTP GET and POST methods defined in RFC 7231 at the Authorization Endpoint'. In the " +
					"conformance suite, failure to correctly respond to an HTTP POST request to the authorization endpoint " +
					"within 30 seconds is considered a WARNING.",
			);
		}
		return env;
	}
}

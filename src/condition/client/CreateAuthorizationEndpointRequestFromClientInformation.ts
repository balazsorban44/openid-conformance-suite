import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateAuthorizationEndpointRequestFromClientInformation extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"], strings: ["redirect_uri"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const clientId = env.getString("client", "client_id");

		if (!clientId) {
			throw this.error("Couldn't find client ID");
		}

		const redirectUri = env.getString("redirect_uri");

		if (!redirectUri) {
			throw this.error("Couldn't find redirect URI");
		}

		const authorizationEndpointRequest: JsonObject = {};

		authorizationEndpointRequest["client_id"] = clientId;
		authorizationEndpointRequest["redirect_uri"] = redirectUri;

		const scope = env.getString("client", "scope");
		if (scope) {
			authorizationEndpointRequest["scope"] = scope;
		} else {
			this.log("No 'scope' parameter in client configuration - omitting scope from authorization request");
		}

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess("Created authorization endpoint request", authorizationEndpointRequest);

		return env;
	}
}

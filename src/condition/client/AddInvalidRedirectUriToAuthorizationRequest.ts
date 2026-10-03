import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddInvalidRedirectUriToAuthorizationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_endpoint_request"],
		strings: ["redirect_uri"],
	};
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const redirectUri = env.getString("redirect_uri") as string;
		const url = new URL(redirectUri);
		url.pathname += "_invalid";
		const invalidUri = url.toString();

		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;
		delete authorizationEndpointRequest["redirect_uri"];
		authorizationEndpointRequest["redirect_uri"] = invalidUri;

		this.logSuccess("Added invalid redirect_uri to authorization endpoint request", args("redirect_uri", invalidUri));

		return env;
	}
}

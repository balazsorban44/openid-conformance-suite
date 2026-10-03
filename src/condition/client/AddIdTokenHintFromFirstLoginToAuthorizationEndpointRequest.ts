import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddIdTokenHintFromFirstLoginToAuthorizationEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request", "first_id_token"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		const firstIdToken = env.getString("first_id_token", "value") as string;

		authorizationEndpointRequest["id_token_hint"] = firstIdToken;

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess("Added id_token_hint to authorization endpoint request", authorizationEndpointRequest);

		return env;
	}
}

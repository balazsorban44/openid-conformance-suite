import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateAuthorizationEndpointResponseParams } from "./CreateAuthorizationEndpointResponseParams.ts";

export class AddIdTokenToAuthorizationEndpointResponseParams extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: [CreateAuthorizationEndpointResponseParams.ENV_KEY],
		strings: ["id_token"],
	};
	static override post: EnvironmentRequirements = { required: [CreateAuthorizationEndpointResponseParams.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		const params = env.getObject(CreateAuthorizationEndpointResponseParams.ENV_KEY) as JsonObject;

		const idToken = env.getString("id_token");

		params["id_token"] = idToken;

		env.putObject(CreateAuthorizationEndpointResponseParams.ENV_KEY, params);

		this.logSuccess(
			"Added id_token to authorization endpoint response params",
			args(CreateAuthorizationEndpointResponseParams.ENV_KEY, params),
		);

		return env;
	}
}

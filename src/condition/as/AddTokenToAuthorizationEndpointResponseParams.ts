import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateAuthorizationEndpointResponseParams } from "./CreateAuthorizationEndpointResponseParams.ts";

export class AddTokenToAuthorizationEndpointResponseParams extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: [CreateAuthorizationEndpointResponseParams.ENV_KEY],
		strings: ["access_token", "token_type"],
	};
	static override post: EnvironmentRequirements = { required: [CreateAuthorizationEndpointResponseParams.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		const params = env.getObject(CreateAuthorizationEndpointResponseParams.ENV_KEY) as JsonObject;

		const accessToken = env.getString("access_token");
		const tokenType = env.getString("token_type");

		params["access_token"] = accessToken;
		params["token_type"] = tokenType;

		env.putObject(CreateAuthorizationEndpointResponseParams.ENV_KEY, params);

		this.log(
			"Added token and token_type to authorization endpoint response params",
			args(CreateAuthorizationEndpointResponseParams.ENV_KEY, params),
		);

		return env;
	}
}

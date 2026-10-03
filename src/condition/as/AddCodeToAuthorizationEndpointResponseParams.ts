import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateAuthorizationEndpointResponseParams } from "./CreateAuthorizationEndpointResponseParams.ts";

export class AddCodeToAuthorizationEndpointResponseParams extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: [CreateAuthorizationEndpointResponseParams.ENV_KEY],
		strings: ["authorization_code"],
	};
	static override post: EnvironmentRequirements = { required: [CreateAuthorizationEndpointResponseParams.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		const params = env.getObject(CreateAuthorizationEndpointResponseParams.ENV_KEY) as JsonObject;

		const code = env.getString("authorization_code");

		params["code"] = code;

		env.putObject(CreateAuthorizationEndpointResponseParams.ENV_KEY, params);

		this.logSuccess(
			"Added code to authorization endpoint response params",
			args(CreateAuthorizationEndpointResponseParams.ENV_KEY, params),
		);

		return env;
	}
}

import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class RemoveRedirectUriFromAuthorizationEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const req = env.getObject("authorization_endpoint_request") as JsonObject;

		delete req["redirect_uri"];

		env.putObject("authorization_endpoint_request", req);

		return env;
	}
}

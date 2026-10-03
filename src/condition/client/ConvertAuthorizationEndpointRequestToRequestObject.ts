import {
	AbstractCondition,
	args,
	deepCopy,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ConvertAuthorizationEndpointRequestToRequestObject extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["request_object_claims"] };

	override evaluate(env: Environment): Environment {
		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		const requestObjectClaims = deepCopy(authorizationEndpointRequest);

		env.putObject("request_object_claims", requestObjectClaims);

		this.logSuccess("Created request object claims", args("request_object_claims", requestObjectClaims));

		return env;
	}
}

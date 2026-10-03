import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddNonceToAuthorizationEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"], strings: ["nonce"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const nonce = env.getString("nonce");
		if (!nonce) {
			throw this.error("Couldn't find nonce value");
		}

		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		authorizationEndpointRequest["nonce"] = nonce;

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess("Added nonce parameter to request", authorizationEndpointRequest);

		return env;
	}
}

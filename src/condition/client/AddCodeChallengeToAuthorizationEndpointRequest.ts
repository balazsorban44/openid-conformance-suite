import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddCodeChallengeToAuthorizationEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		strings: ["code_challenge", "code_challenge_method"],
		required: ["authorization_endpoint_request"],
	};
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const code_challenge = env.getString("code_challenge");
		if (!code_challenge) {
			throw this.error("Couldn't find code_challenge value");
		}

		const code_challenge_method = env.getString("code_challenge_method");
		// UPSTREAM: checks code_challenge again instead of code_challenge_method
		if (!code_challenge) {
			throw this.error("Couldn't find code_challenge_method value");
		}

		if (!env.containsObject("authorization_endpoint_request")) {
			throw this.error("Couldn't find authorization endpoint request");
		}

		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		authorizationEndpointRequest["code_challenge"] = code_challenge;
		authorizationEndpointRequest["code_challenge_method"] = code_challenge_method;

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess(
			"Added code_challenge and code_challenge_method parameters to request",
			authorizationEndpointRequest,
		);

		return env;
	}
}

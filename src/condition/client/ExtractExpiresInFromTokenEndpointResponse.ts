import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ExtractExpiresInFromTokenEndpointResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };
	static override post: EnvironmentRequirements = { required: ["expires_in"] };

	override evaluate(env: Environment): Environment {
		const tokenEndpoint = env.getObject("token_endpoint_response") as JsonObject;
		const expiresInValue = tokenEndpoint["expires_in"];

		if (expiresInValue === undefined) {
			throw this.error(
				"'expires_in' not present in the token endpoint response. RFC6749 recommends expires_in is included.",
				tokenEndpoint,
			);
		}

		/* Create our cut down JsonObject with just a single value in it */
		const value: JsonObject = {};
		value["expires_in"] = expiresInValue;

		env.putObject("expires_in", value);

		this.logSuccess("Extracted 'expires_in'", value);

		return env;
	}
}

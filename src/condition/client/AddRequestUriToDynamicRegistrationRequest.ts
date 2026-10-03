import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
	type JsonArray,
} from "../../framework/index.ts";

export class AddRequestUriToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request", "request_uri"] };
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		const requestUri = env.getString("request_uri", "fullUrl");
		if (!requestUri) {
			throw this.error("No request_uri found in environment; this is likely a bug in the test module");
		}

		const requestUris: JsonArray = [];
		requestUris.push(requestUri);
		dynamicRegistrationRequest["request_uris"] = requestUris;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added request_uris array to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}

import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckEndpointContentTypeReturned } from "./AbstractCheckEndpointContentTypeReturned.ts";

export class EnsureContentTypeJson extends AbstractCheckEndpointContentTypeReturned {
	static endpointResponseWasJsonKey = "endpoint_response_was_json";

	static override pre: EnvironmentRequirements = { required: ["endpoint_response"] };

	override evaluate(env: Environment): Environment {
		env.putBoolean(EnsureContentTypeJson.endpointResponseWasJsonKey, false);

		env = this.checkContentType(env, "endpoint_response", "headers.", "application/json");

		env.putBoolean(EnsureContentTypeJson.endpointResponseWasJsonKey, true);

		return env;
	}
}

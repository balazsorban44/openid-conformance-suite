import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckEndpointContentTypeReturned } from "./AbstractCheckEndpointContentTypeReturned.ts";

export class CheckTokenEndpointReturnedJsonContentType extends AbstractCheckEndpointContentTypeReturned {
	static tokenEndpointResponseWasJsonKey = "token_endpoint_response_was_json";

	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response_headers"] };

	override evaluate(env: Environment): Environment {
		env.putBoolean(CheckTokenEndpointReturnedJsonContentType.tokenEndpointResponseWasJsonKey, false);

		env = this.checkContentType(env, "token_endpoint_response_headers", "", "application/json");

		env.putBoolean(CheckTokenEndpointReturnedJsonContentType.tokenEndpointResponseWasJsonKey, true);

		return env;
	}
}

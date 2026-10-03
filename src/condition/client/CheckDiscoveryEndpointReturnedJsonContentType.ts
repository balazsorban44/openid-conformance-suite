import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckEndpointContentTypeReturned } from "./AbstractCheckEndpointContentTypeReturned.ts";

export class CheckDiscoveryEndpointReturnedJsonContentType extends AbstractCheckEndpointContentTypeReturned {
	static override pre: EnvironmentRequirements = { required: ["discovery_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		env = this.checkContentType(env, "discovery_endpoint_response", "headers.", "application/json");

		return env;
	}
}

import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckEndpointContentTypeReturned } from "./AbstractCheckEndpointContentTypeReturned.ts";

export class EnsureContentTypeApplicationJwt extends AbstractCheckEndpointContentTypeReturned {
	static override pre: EnvironmentRequirements = { required: ["endpoint_response"] };

	override evaluate(env: Environment): Environment {
		env = this.checkContentType(env, "endpoint_response", "headers.", "application/jwt");

		return env;
	}
}

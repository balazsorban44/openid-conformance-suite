import { type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { AbstractValidateResponseCacheHeaders } from "../AbstractValidateResponseCacheHeaders.ts";

export class CheckTokenEndpointCacheHeaders extends AbstractValidateResponseCacheHeaders {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response_headers"] };

	override evaluate(env: Environment): Environment {
		const headers = env.getObject("token_endpoint_response_headers") as JsonObject;
		const humanReadableResponseName = "token endpoint response";

		this.validateCacheHeaders(headers, humanReadableResponseName);

		return env;
	}
}

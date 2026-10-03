import type { Environment, EnvironmentRequirements, JsonObject } from "../../../framework/index.ts";
import { AbstractValidateResponseCacheHeaders } from "../../AbstractValidateResponseCacheHeaders.ts";

export class EnsureBackChannelLogoutEndpointResponseContainsCacheHeaders extends AbstractValidateResponseCacheHeaders {
	static override pre: EnvironmentRequirements = { required: ["backchannel_logout_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const headers = env.getElementFromObject("backchannel_logout_endpoint_response", "headers") as JsonObject;
		const humanReadableResponseName = "RP backchannel_logout_uri response";

		this.validateCacheHeaders(headers, humanReadableResponseName);

		return env;
	}
}

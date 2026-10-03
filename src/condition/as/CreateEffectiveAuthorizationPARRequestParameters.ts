import { type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

/**
 * Merges http request parameters and unsigned PAR and request object parameters
 * and creates effective_authorization_endpoint_request environment entry
 */
export class CreateEffectiveAuthorizationPARRequestParameters extends CreateEffectiveAuthorizationRequestParameters {
	//WARNING "authorization_request_object" is also used but it's not required
	static override pre: EnvironmentRequirements = {
		required: ["authorization_endpoint_http_request_params", "par_endpoint_http_request_params"],
	};
	static override post: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		return super.evaluate(env);
	}

	protected override customizeEffectiveAuthorizationRequestParams(env: Environment, effective: JsonObject): void {
		const parEndpointReqParams = env.getObject("par_endpoint_http_request_params") as JsonObject;
		delete effective["client_assertion"];
		delete effective["client_assertion_type"];
		delete effective["client_secret"];

		// overrride with unsigned PAR params
		for (const paramName of Object.keys(parEndpointReqParams)) {
			effective[paramName] = parEndpointReqParams[paramName];
		}
	}
}

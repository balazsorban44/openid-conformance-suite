import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import {
	AbstractAddClaimToAuthorizationEndpointRequest,
	LocationToRequestClaim,
} from "./AbstractAddClaimToAuthorizationEndpointRequest.ts";

export class AddIdTokenEssentialNameClaimToAuthorizationEndpointRequest extends AbstractAddClaimToAuthorizationEndpointRequest {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		return this.addClaim(env, LocationToRequestClaim.ID_TOKEN, "name", null, true);
	}
}

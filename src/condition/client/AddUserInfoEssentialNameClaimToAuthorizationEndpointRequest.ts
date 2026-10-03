import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import {
	AbstractAddClaimToAuthorizationEndpointRequest,
	LocationToRequestClaim,
} from "./AbstractAddClaimToAuthorizationEndpointRequest.ts";

export class AddUserInfoEssentialNameClaimToAuthorizationEndpointRequest extends AbstractAddClaimToAuthorizationEndpointRequest {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		/*
		The python suite sends:

		https://fapidev-www.authlete.net/api/authorization?state=9d4Uoc5cCHR3nVLC&nonce=ilTAjEj9bdysSoSX&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fop.certification.openid.net%3A61757%2Fauthz_cb&claims=%7B%22userinfo%22%3A+%7B%22name%22%3A+%7B%22essential%22%3A+true%7D%7D%7D&client_id=138292314413510

		or the decoded claims value:

		"userinfo": {
			"name": {
				"essential": true
			}
		}

		 */

		return this.addClaim(env, LocationToRequestClaim.USERINFO, "name", null, true);
	}
}

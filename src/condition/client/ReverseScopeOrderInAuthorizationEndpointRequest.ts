import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractReverseScopeOrder } from "./AbstractReverseScopeOrder.ts";

export class ReverseScopeOrderInAuthorizationEndpointRequest extends AbstractReverseScopeOrder {
	static readonly envKey = "authorization_endpoint_request";

	static override pre: EnvironmentRequirements = {
		required: [ReverseScopeOrderInAuthorizationEndpointRequest.envKey],
	};
	static override post: EnvironmentRequirements = {
		required: [ReverseScopeOrderInAuthorizationEndpointRequest.envKey],
	};

	override evaluate(env: Environment): Environment {
		this.reverseScope(env, ReverseScopeOrderInAuthorizationEndpointRequest.envKey);

		return env;
	}
}

import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractAddGrantTypeToDynamicRegistrationRequest } from "./AbstractAddGrantTypeToDynamicRegistrationRequest.ts";

export class AddRefreshTokenGrantTypeToDynamicRegistrationRequest extends AbstractAddGrantTypeToDynamicRegistrationRequest {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		this.addGrantType(env, "refresh_token");

		return env;
	}
}

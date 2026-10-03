import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractAddGrantTypeToDynamicRegistrationRequest } from "./AbstractAddGrantTypeToDynamicRegistrationRequest.ts";

export class AddAuthorizationCodeGrantTypeToDynamicRegistrationRequest extends AbstractAddGrantTypeToDynamicRegistrationRequest {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		this.addGrantType(env, "authorization_code");

		return env;
	}
}

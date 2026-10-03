import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateErrorDescriptionFromResponseError } from "./AbstractValidateErrorDescriptionFromResponseError.ts";

export class ValidateErrorDescriptionFromAuthorizationEndpointResponseError extends AbstractValidateErrorDescriptionFromResponseError {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		return this.validateErrorDescription(env, "authorization_endpoint_response");
	}
}

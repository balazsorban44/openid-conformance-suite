import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateErrorUriFromResponseError } from "./AbstractValidateErrorUriFromResponseError.ts";

export class ValidateErrorUriFromAuthorizationEndpointResponseError extends AbstractValidateErrorUriFromResponseError {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		return this.checkErrorUri(env, "authorization_endpoint_response");
	}
}

import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateErrorDescriptionFromResponseError } from "./AbstractValidateErrorDescriptionFromResponseError.ts";

export class ValidateErrorDescriptionFromTokenEndpointResponseError extends AbstractValidateErrorDescriptionFromResponseError {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		return this.validateErrorDescription(env, "token_endpoint_response");
	}
}

import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateErrorUriFromResponseError } from "./AbstractValidateErrorUriFromResponseError.ts";

export class ValidateErrorUriFromTokenEndpointResponseError extends AbstractValidateErrorUriFromResponseError {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		return this.checkErrorUri(env, "token_endpoint_response");
	}
}

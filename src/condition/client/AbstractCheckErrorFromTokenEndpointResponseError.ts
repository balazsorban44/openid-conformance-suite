import type { EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckErrorFromResponseError } from "./AbstractCheckErrorFromResponseError.ts";

export abstract class AbstractCheckErrorFromTokenEndpointResponseError extends AbstractCheckErrorFromResponseError {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	protected override getResponseKey(): string {
		return "token_endpoint_response";
	}
}

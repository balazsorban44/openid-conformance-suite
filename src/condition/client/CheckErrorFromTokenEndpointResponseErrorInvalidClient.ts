import { AbstractCheckErrorFromTokenEndpointResponseError } from "./AbstractCheckErrorFromTokenEndpointResponseError.ts";

export class CheckErrorFromTokenEndpointResponseErrorInvalidClient extends AbstractCheckErrorFromTokenEndpointResponseError {
	protected override getExpectedError(): string[] {
		return ["invalid_client"];
	}
}

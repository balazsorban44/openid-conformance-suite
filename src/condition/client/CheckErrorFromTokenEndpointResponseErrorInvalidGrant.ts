import { AbstractCheckErrorFromTokenEndpointResponseError } from "./AbstractCheckErrorFromTokenEndpointResponseError.ts";

export class CheckErrorFromTokenEndpointResponseErrorInvalidGrant extends AbstractCheckErrorFromTokenEndpointResponseError {
	protected override getExpectedError(): string[] {
		return ["invalid_grant"];
	}
}

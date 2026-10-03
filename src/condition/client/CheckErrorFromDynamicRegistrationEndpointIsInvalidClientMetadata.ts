import { AbstractCheckErrorFromDynamicRegistrationEndpoint } from "./AbstractCheckErrorFromDynamicRegistrationEndpoint.ts";

export class CheckErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata extends AbstractCheckErrorFromDynamicRegistrationEndpoint {
	protected override getPermittedErrors(): string[] {
		return ["invalid_client_metadata"];
	}
}

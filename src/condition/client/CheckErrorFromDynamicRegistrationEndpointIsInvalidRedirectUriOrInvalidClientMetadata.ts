import { AbstractCheckErrorFromDynamicRegistrationEndpoint } from "./AbstractCheckErrorFromDynamicRegistrationEndpoint.ts";

export class CheckErrorFromDynamicRegistrationEndpointIsInvalidRedirectUriOrInvalidClientMetadata extends AbstractCheckErrorFromDynamicRegistrationEndpoint {
	protected override getPermittedErrors(): string[] {
		return ["invalid_redirect_uri", "invalid_client_metadata"];
	}
}

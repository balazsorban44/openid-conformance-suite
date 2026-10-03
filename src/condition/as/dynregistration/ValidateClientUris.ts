import { AbstractValidateUrisBasedOnHttpStatusCodeOnly } from "./AbstractValidateUrisBasedOnHttpStatusCodeOnly.ts";

/**
 * client_uri
 * OPTIONAL. URL of the home page of the Client. The value of this field MUST point to a valid Web page.
 * If present, the server SHOULD display this URL to the End-User in a followable fashion.
 * If desired, representation of this Claim in different languages and scripts is represented as
 * described in Section 2.1.
 *
 * This class just checks if the uri returns a http response < 400
 */
export class ValidateClientUris extends AbstractValidateUrisBasedOnHttpStatusCodeOnly {
	protected override getUrisToTest(): Map<string, string> {
		return this.getAllClientUris();
	}

	protected override getMetadataName(): string {
		return "client_uri";
	}
}

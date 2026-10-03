import type { PublishTestModule } from "../../framework/index.ts";
import { AddInvalidIssValueToIdToken } from "../../condition/as/AddInvalidIssValueToIdToken.ts";
import { AbstractOIDCCClientTestExpectingNothingInvalidIdToken } from "./AbstractOIDCCClientTestExpectingNothingInvalidIdToken.ts";

export class OIDCCClientTestInvalidIssuerInIdToken extends AbstractOIDCCClientTestExpectingNothingInvalidIdToken {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-invalid-iss",
		displayName: "OIDCC: Relying party test. Invalid iss value in id token.",
		summary:
			"The client must identify that the 'iss' value is incorrect and reject the ID Token after doing ID Token validation." +
			" Corresponds to rp-id_token-issuer-mismatch test in the old test suite",
		profile: "OIDCC",
		configurationFields: ["waitTimeoutSeconds"],
	};

	protected override async generateIdTokenClaims(): Promise<void> {
		await super.generateIdTokenClaims();
		await this.callAndStopOnFailure(AddInvalidIssValueToIdToken, "OIDCC-3.1.3.7");
	}

	protected override getAuthorizationCodeGrantTypeErrorMessage(): string {
		return "Client has incorrectly called token_endpoint after receiving an id_token with an invalid iss claim from the authorization_endpoint.";
	}

	protected override getHandleUserinfoEndpointRequestErrorMessage(): string {
		return "Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid iss claim.";
	}
}

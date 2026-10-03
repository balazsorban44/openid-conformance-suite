import type { PublishTestModule } from "../../framework/index.ts";
import { AddInvalidAudValueToIdToken } from "../../condition/as/AddInvalidAudValueToIdToken.ts";
import { AbstractOIDCCClientTestExpectingNothingInvalidIdToken } from "./AbstractOIDCCClientTestExpectingNothingInvalidIdToken.ts";

export class OIDCCClientTestInvalidAudInIdToken extends AbstractOIDCCClientTestExpectingNothingInvalidIdToken {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-invalid-aud",
		displayName: "OIDCC: Relying party test. Invalid aud value in id token.",
		summary:
			"The client must identify that the 'aud' value is incorrect and reject the ID Token after doing ID Token validation." +
			" Corresponds to rp-id_token-aud test in the old test suite",
		profile: "OIDCC",
		configurationFields: ["waitTimeoutSeconds"],
	};

	protected override async generateIdTokenClaims(): Promise<void> {
		await super.generateIdTokenClaims();
		await this.callAndStopOnFailure(AddInvalidAudValueToIdToken, "OIDCC-3.1.3.7", "OIDCC-2");
	}

	protected override getAuthorizationCodeGrantTypeErrorMessage(): string {
		return "Client has incorrectly called token_endpoint after receiving an id_token with an invalid aud claim from the authorization_endpoint.";
	}

	protected override getHandleUserinfoEndpointRequestErrorMessage(): string {
		return "Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid aud claim.";
	}
}

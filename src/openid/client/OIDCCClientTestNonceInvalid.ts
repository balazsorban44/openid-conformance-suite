import type { PublishTestModule } from "../../framework/index.ts";
import { AddInvalidNonceValueToIdToken } from "../../condition/as/AddInvalidNonceValueToIdToken.ts";
import { AbstractOIDCCClientTestExpectingNothingInvalidIdToken } from "./AbstractOIDCCClientTestExpectingNothingInvalidIdToken.ts";

export class OIDCCClientTestNonceInvalid extends AbstractOIDCCClientTestExpectingNothingInvalidIdToken {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-nonce-invalid",
		displayName: "OIDCC: Relying party test. Invalid nonce in id token.",
		summary:
			"The client must identify that the 'nonce' value in the ID Token is invalid and must reject the ID Token." +
			" Corresponds to rp-nonce-invalid test in the old test suite",
		profile: "OIDCC",
		configurationFields: ["waitTimeoutSeconds"],
	};

	protected override async generateIdTokenClaims(): Promise<void> {
		await super.generateIdTokenClaims();
		await this.callAndStopOnFailure(AddInvalidNonceValueToIdToken, "OIDCC-2");
	}

	protected override getAuthorizationCodeGrantTypeErrorMessage(): string {
		return "Client has incorrectly called token_endpoint after receiving an id_token with an invalid nonce value from the authorization_endpoint.";
	}

	protected override getHandleUserinfoEndpointRequestErrorMessage(): string {
		return "Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid nonce value.";
	}
}

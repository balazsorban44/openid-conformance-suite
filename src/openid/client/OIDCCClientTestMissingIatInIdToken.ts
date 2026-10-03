import type { PublishTestModule } from "../../framework/index.ts";
import { RemoveIatFromIdToken } from "../../condition/as/RemoveIatFromIdToken.ts";
import { AbstractOIDCCClientTestExpectingNothingInvalidIdToken } from "./AbstractOIDCCClientTestExpectingNothingInvalidIdToken.ts";

export class OIDCCClientTestMissingIatInIdToken extends AbstractOIDCCClientTestExpectingNothingInvalidIdToken {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-missing-iat",
		displayName: "OIDCC: Relying party test. Missing iat value in id token.",
		summary:
			"The client must identify the missing 'iat' value and reject the ID Token after doing ID Token validation." +
			" Corresponds to rp-id_token-iat test in the old test suite",
		profile: "OIDCC",
		configurationFields: ["waitTimeoutSeconds"],
	};

	protected override async generateIdTokenClaims(): Promise<void> {
		await super.generateIdTokenClaims();
		await this.callAndStopOnFailure(RemoveIatFromIdToken, "OIDCC-2");
	}

	protected override getAuthorizationCodeGrantTypeErrorMessage(): string {
		return "Client has incorrectly called token_endpoint after receiving an id_token with no iat claim from the authorization_endpoint.";
	}

	protected override getHandleUserinfoEndpointRequestErrorMessage(): string {
		return "Client has incorrectly called userinfo_endpoint after receiving an id_token with no iat claim.";
	}
}

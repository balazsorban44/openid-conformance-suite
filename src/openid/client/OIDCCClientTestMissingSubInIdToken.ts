import type { PublishTestModule } from "../../framework/index.ts";
import { RemoveSubFromIdToken } from "../../condition/as/RemoveSubFromIdToken.ts";
import { AbstractOIDCCClientTestExpectingNothingInvalidIdToken } from "./AbstractOIDCCClientTestExpectingNothingInvalidIdToken.ts";

export class OIDCCClientTestMissingSubInIdToken extends AbstractOIDCCClientTestExpectingNothingInvalidIdToken {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-missing-sub",
		displayName: "OIDCC: Relying party test. No sub in id_token.",
		summary:
			"The client must identify the missing 'sub' claim and must reject the ID Token." +
			" Corresponds to rp-id_token-sub test in the old test suite",
		profile: "OIDCC",
		configurationFields: ["waitTimeoutSeconds"],
	};

	protected override async generateIdTokenClaims(): Promise<void> {
		await super.generateIdTokenClaims();
		await this.callAndStopOnFailure(RemoveSubFromIdToken, "OIDCC-2");
	}

	protected override getAuthorizationCodeGrantTypeErrorMessage(): string {
		return "Client has incorrectly called token_endpoint after receiving an id_token without a sub value from the authorization_endpoint.";
	}

	protected override getHandleUserinfoEndpointRequestErrorMessage(): string {
		return "Client has incorrectly called userinfo_endpoint after receiving an id_token without a sub value.";
	}
}

import { ExpectInvalidIdTokenHintErrorPage } from "../condition/client/ExpectInvalidIdTokenHintErrorPage.ts";
import { GenerateFakeIdTokenClaims } from "../condition/client/GenerateFakeIdTokenClaims.ts";
import { GenerateJWKsFromClientSecret } from "../condition/client/GenerateJWKsFromClientSecret.ts";
import { SignFakeIdToken } from "../condition/client/SignFakeIdToken.ts";
import { TestFailureException, type HttpSession, type IncomingHttpRequest, type JsonObject, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCRpInitiatedLogout } from "./AbstractOIDCCRpInitiatedLogout.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_RpInitLogout_Wrong_id_token_hint
// https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-RpInitLogout-Wrong-id_token_hint.json
export class OIDCCRpInitiatedLogoutBadIdTokenHint extends AbstractOIDCCRpInitiatedLogout {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-rp-initiated-logout-bad-id-token-hint",
		displayName: "OIDCC: rp initiated logout - bad id_token_hint",
		summary:
			"This test performs a normal authorization flow at the OP, then sends the user to the end_session_endpoint with an id_token_hint signed by the test suite.\n\nThe OP must not redirect back and must either show an error screen or confirm with the user if they want to logout - a screenshot of which should be uploaded.",
		profile: "OIDCC",
	};

	protected override async onConfigure(config: JsonObject, baseUrl: string): Promise<void> {
		await super.onConfigure(config, baseUrl);
		if (this.env.getObject("client_jwks") == null) {
			// we need a client jwks for SignFakeIdToken
			await this.callAndStopOnFailure(GenerateJWKsFromClientSecret);
		}
	}

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		await this.callAndStopOnFailure(GenerateFakeIdTokenClaims);
		await this.callAndStopOnFailure(SignFakeIdToken);
		await super.onPostAuthorizationFlowComplete();
	}

	override async handleHttp(
		path: string,
		req: IncomingHttpRequest,
		res: unknown,
		session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		if (path === "post_logout_redirect") {
			throw new TestFailureException(
				this.getId(),
				"OP has incorrectly called the registered post_logout_redirect_uri even though an invalid id_token_hint was provided.",
			);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	protected override async createLogoutPlaceholder(): Promise<string | null> {
		await this.callAndStopOnFailure(ExpectInvalidIdTokenHintErrorPage, "OIDCRIL-2");

		return this.env.getString("invalid_id_token_hint_error");
	}
}

import { ChangeIdTokenToAlgNone } from "../condition/client/ChangeIdTokenToAlgNone.ts";
import { ExpectInvalidIdTokenHintErrorPage } from "../condition/client/ExpectInvalidIdTokenHintErrorPage.ts";
import { TestFailureException, type HttpSession, type IncomingHttpRequest, type JsonObject, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCRpInitiatedLogout } from "./AbstractOIDCCRpInitiatedLogout.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_RpInitLogout_Modified_id_token_hint
// https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-RpInitLogout-Modified-id_token_hint.json
export class OIDCCRpInitiatedLogoutModifiedIdTokenHint extends AbstractOIDCCRpInitiatedLogout {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-rp-initiated-logout-modified-id-token-hint",
		displayName: "OIDCC: rp initiated logout - modified id_token_hint",
		summary:
			"This test performs a normal authorization flow at the OP, then sends the user to the end_session_endpoint with an id_token_hint that has been changed to alg:none.\n\nThe OP must not redirect back and must either show an error screen or confirm with the user if they want to logout - a screenshot of which should be uploaded.",
		profile: "OIDCC",
	};

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		await this.callAndStopOnFailure(ChangeIdTokenToAlgNone);
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

import { ExpectSuccessfulLogoutPage } from "../condition/client/ExpectSuccessfulLogoutPage.ts";
import { RemoveIdTokenHintFromEndSessionEndpointRequest } from "../condition/client/RemoveIdTokenHintFromEndSessionEndpointRequest.ts";
import { RemovePostLogoutRedirectUriFromEndSessionEndpointRequest } from "../condition/client/RemovePostLogoutRedirectUriFromEndSessionEndpointRequest.ts";
import { TestFailureException, type HttpSession, type IncomingHttpRequest, type JsonObject, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCRpInitiatedLogout } from "./AbstractOIDCCRpInitiatedLogout.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_RpInitLogout_Only_state
export class OIDCCRpInitiatedLogoutOnlyState extends AbstractOIDCCRpInitiatedLogout {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-rp-initiated-logout-only-state",
		displayName: "OIDCC: rp initiated logout - only state",
		summary:
			"This test performs a normal authorization flow at the OP, then sends the user to the end_session_endpoint with only a state parameter - the OP must log the user out, a screenshot of the 'you are logged out' screen should be uploaded.",
		profile: "OIDCC",
	};

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
				"OP has incorrectly called the registered post_logout_redirect_uri when it wasn't in the request.",
			);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	protected override async customiseEndSessionEndpointRequest(): Promise<void> {
		await this.callAndStopOnFailure(RemoveIdTokenHintFromEndSessionEndpointRequest);
		await this.callAndStopOnFailure(RemovePostLogoutRedirectUriFromEndSessionEndpointRequest);
	}

	protected override async createLogoutPlaceholder(): Promise<string | null> {
		await this.callAndStopOnFailure(ExpectSuccessfulLogoutPage, "OIDCRIL-2");

		return this.env.getString("successful_logout_page");
	}
}

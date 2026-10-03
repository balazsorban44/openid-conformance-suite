import { AddPostLogoutRedirectUriWithQueryAddedToEndSessionEndpointRequest } from "../condition/client/AddPostLogoutRedirectUriWithQueryAddedToEndSessionEndpointRequest.ts";
import { ExpectPostLogoutRedirectUriNotRegisteredErrorPage } from "../condition/client/ExpectPostLogoutRedirectUriNotRegisteredErrorPage.ts";
import {
	TestFailureException,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonObject,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCRpInitiatedLogout } from "./AbstractOIDCCRpInitiatedLogout.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_RpInitLogout_Unregistered_post_logout_redirect_uri
export class OIDCCRpInitiatedLogoutQueryAddedToLogoutRedirectUri extends AbstractOIDCCRpInitiatedLogout {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri",
		displayName: "OIDCC: rp initiated logout - query added to post_logout_redirect_uri",
		summary:
			"This test performs a normal authorization flow at the OP, then sends the user to the end_session_endpoint with a post_logout_redirect_uri that has had '?foo=bar' added.\n\nThe OP must not redirect back and must either show an error screen or confirm with the user if they want to logout - a screenshot of which should be uploaded.",
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
				"OP has incorrectly called the registered post_logout_redirect_uri even though a different uri was requested.",
			);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	protected override async customiseEndSessionEndpointRequest(): Promise<void> {
		await this.callAndStopOnFailure(AddPostLogoutRedirectUriWithQueryAddedToEndSessionEndpointRequest);
	}

	protected override async createLogoutPlaceholder(): Promise<string | null> {
		await this.callAndStopOnFailure(ExpectPostLogoutRedirectUriNotRegisteredErrorPage, "OIDCRIL-2");

		return this.env.getString("post_logout_redirect_uri_not_registered_error");
	}
}

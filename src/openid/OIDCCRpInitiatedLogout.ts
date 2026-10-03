import { CheckForUnexpectedParametersInPostLogoutRedirect } from "../condition/client/CheckForUnexpectedParametersInPostLogoutRedirect.ts";
import { CheckPostLogoutState } from "../condition/client/CheckPostLogoutState.ts";
import {
	ConditionResult,
	modelAndView,
	Status,
	TestFailureException,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonObject,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCRpInitiatedLogout } from "./AbstractOIDCCRpInitiatedLogout.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_RpInitLogout
// https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-RpInitLogout.json
export class OIDCCRpInitiatedLogout extends AbstractOIDCCRpInitiatedLogout {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-rp-initiated-logout",
		displayName: "OIDCC: rp initiated logout",
		summary:
			"This test performs a normal authorization flow at the OP, then sends the user to the end_session_endpoint. It validates the OP correctly sends the user to the post_logout_redirect_uri, then tries another authentication with prompt=none which must return an error (as the user has been logged out).\n\nIf using static client registration you must register a post_logout_redirect_uri, the same url as the redirect url but replacing the portion after the alias with '/post_logout_redirect'.",
		profile: "OIDCC",
	};

	protected async validateLogoutResults(requestParts: JsonObject): Promise<void> {
		this.env.putObject("post_logout_redirect", requestParts);

		this.eventLog.startBlock("Verify frontchannel post logout redirect");
		await this.callAndContinueOnFailure(CheckPostLogoutState, ConditionResult.FAILURE, "OIDCRIL-2");
		await this.callAndContinueOnFailure(
			CheckForUnexpectedParametersInPostLogoutRedirect,
			ConditionResult.WARNING,
			"OIDCRIL-2",
		);
		this.eventLog.endBlock();

		// do the prompt=none authorization request to check logout happened
		await this.performAuthorizationFlow();
	}

	override async handleHttp(
		path: string,
		req: IncomingHttpRequest,
		res: unknown,
		session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		if (path === "post_logout_redirect") {
			return this.handlePostLogoutRedirect(requestParts);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	protected handlePostLogoutRedirect(requestParts: JsonObject): Response {
		this.getTestExecutionManager().runInBackground(async () => {
			await this.setStatus(Status.RUNNING);

			if (!this.expectingLogoutConfirmation) {
				throw new TestFailureException(this.getId(), "post_logout_redirect called when not expected");
			}
			this.expectingLogoutConfirmation = false;

			await this.validateLogoutResults(requestParts);

			return "done";
		});

		return modelAndView("resultCaptured", {
			returnUrl: "/log-detail.html?log=" + this.getId(),
		});
	}
}

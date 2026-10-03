import { CheckForUnexpectedParametersInPostLogoutRedirect } from "../condition/client/CheckForUnexpectedParametersInPostLogoutRedirect.ts";
import { CheckNoPostLogoutState } from "../condition/client/CheckNoPostLogoutState.ts";
import { RemoveStateFromEndSessionEndpointRequest } from "../condition/client/RemoveStateFromEndSessionEndpointRequest.ts";
import {
	ConditionResult,
	modelAndView,
	Status,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonObject,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCRpInitiatedLogout } from "./AbstractOIDCCRpInitiatedLogout.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_RpInitLogout_No_state
export class OIDCCRpInitiatedLogoutNoState extends AbstractOIDCCRpInitiatedLogout {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-rp-initiated-logout-no-state",
		displayName: "OIDCC: rp initiated logout",
		summary:
			"This test performs a normal authorization flow at the OP, then sends the user to the end_session_endpoint with no state parameter. It validates the OP correctly sends the user to the post_logout_redirect_uri with no state, then tries another authentication with prompt=none which must return an error (as the user has been logged out).\n\nIf using static client registration you must register a post_logout_redirect_uri, the same url as the redirect url but replacing the portion after the alias with '/post_logout_redirect'.",
		profile: "OIDCC",
	};

	protected async validateLogoutResults(requestParts: JsonObject): Promise<void> {
		this.env.putObject("post_logout_redirect", requestParts);

		this.eventLog.startBlock("Verify frontchannel post logout redirect");
		await this.callAndContinueOnFailure(CheckNoPostLogoutState, ConditionResult.FAILURE, "OIDCRIL-2");
		await this.callAndContinueOnFailure(
			CheckForUnexpectedParametersInPostLogoutRedirect,
			ConditionResult.WARNING,
			"OIDCRIL-3",
		);
		this.eventLog.endBlock();

		// do the prompt=none authorization request to check logout happened
		await this.performAuthorizationFlow();
	}

	protected override async customiseEndSessionEndpointRequest(): Promise<void> {
		await this.callAndStopOnFailure(RemoveStateFromEndSessionEndpointRequest);
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

			await this.validateLogoutResults(requestParts);

			return "done";
		});

		return modelAndView("resultCaptured", {
			returnUrl: "/log-detail.html?log=" + this.getId(),
		});
	}
}

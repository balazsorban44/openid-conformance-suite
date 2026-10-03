import { CheckDiscCheckSessionIframe } from "../condition/client/CheckDiscCheckSessionIframe.ts";
import { CheckForUnexpectedParametersInPostLogoutRedirect } from "../condition/client/CheckForUnexpectedParametersInPostLogoutRedirect.ts";
import { CheckPostLogoutState } from "../condition/client/CheckPostLogoutState.ts";
import { CheckSecondSessionResultIsChanged } from "../condition/client/CheckSecondSessionResultIsChanged.ts";
import { CheckSessionResultIsUnchanged } from "../condition/client/CheckSessionResultIsUnchanged.ts";
import { ExtractSessionStateFromAuthorizationResponse } from "../condition/client/ExtractSessionStateFromAuthorizationResponse.ts";
import {
	args,
	ConditionResult,
	modelAndView,
	Status,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonObject,
	type PublishTestModule,
} from "../framework/index.ts";
import "../framework/views/rpSessionIframe.ts";
import "../framework/views/sessionVerify.ts";
import { AbstractOIDCCRpInitiatedLogout } from "./AbstractOIDCCRpInitiatedLogout.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_Session_RpInitLogout
// https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-Session-RpInitLogout.json
export class OIDCCSessionManagementRpInitiatedLogout extends AbstractOIDCCRpInitiatedLogout {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-session-management-rp-initiated-logout",
		displayName: "OIDCC: Session management - rp initiated logout",
		summary:
			"This test performs a normal authorization flow at the OP, then sends the user to the end_session_endpoint, and uses check_session_iframe to check the session state before and after the logout.\n\nIf using static client registration you must register a post_logout_redirect_uri, the same url as the redirect url but replacing the portion after the alias with '/post_logout_redirect'.\n\nPlease note that this test may not work in some browsers.",
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

		await this.checkSessionState(false);
	}

	protected override async onConfigure(config: JsonObject, baseUrl: string): Promise<void> {
		await super.onConfigure(config, baseUrl);
		await this.callAndStopOnFailure(CheckDiscCheckSessionIframe, "OIDCSM-3.3");
	}

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		await this.checkSessionState(true);
	}

	private async checkSessionState(firstTime: boolean): Promise<void> {
		// check session state with iframe
		await this.callAndStopOnFailure(ExtractSessionStateFromAuthorizationResponse, "OIDCSM-2");

		const redirectTo = this.env.getString("base_url") + (firstTime ? "/session_verify" : "/second_session_verify");

		this.eventLog.log(
			this.getName(),
			args("msg", "Redirecting to our session check page", "redirect_to", redirectTo, "http", "redirect"),
		);

		await this.setStatus(Status.WAITING);

		this.browser.goToUrl(redirectTo);
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
		} else if (path === "session_verify") {
			return this.handleSessionVerify(requestParts, true);
		} else if (path === "second_session_verify") {
			return this.handleSessionVerify(requestParts, false);
		} else if (path === "rp_session_iframe") {
			return this.handleRpSessionIframe(requestParts, true);
		} else if (path === "second_rp_session_iframe") {
			return this.handleRpSessionIframe(requestParts, false);
		} else if (path === "session_result") {
			return this.handleSessionResult(requestParts, true);
		} else if (path === "second_session_result") {
			return this.handleSessionResult(requestParts, false);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	protected async validateFirstSessionCheckResult(requestParts: JsonObject): Promise<void> {
		this.env.putObject("session_result", requestParts);
		await this.callAndContinueOnFailure(CheckSessionResultIsUnchanged, ConditionResult.FAILURE, "OIDCSM-3.1");

		// now carry on and log the user out
		await super.onPostAuthorizationFlowComplete();
	}

	protected async validateSecondSessionCheckResult(requestParts: JsonObject): Promise<void> {
		this.env.putObject("second_session_result", requestParts);
		await this.callAndContinueOnFailure(CheckSecondSessionResultIsChanged, ConditionResult.FAILURE, "OIDCSM-3.1");

		// we could call performAuthorizationFlow() to do a prompt=none authorization request to check logout
		// happened, but the python didn't so don't
		await this.fireTestFinished();
	}

	protected handleSessionResult(requestParts: JsonObject, firstTime: boolean): Response {
		this.getTestExecutionManager().runInBackground(async () => {
			await this.setStatus(Status.RUNNING);

			if (firstTime) {
				await this.validateFirstSessionCheckResult(requestParts);
			} else {
				await this.validateSecondSessionCheckResult(requestParts);
			}

			return "done";
		});

		return modelAndView("resultCaptured", {
			returnUrl: "/log-detail.html?log=" + this.getId(),
		});
	}

	protected async handleSessionVerify(_requestParts: JsonObject, firstTime: boolean): Promise<Response> {
		await this.setStatus(Status.RUNNING);

		const checkSessionIframeUrl = this.env.getString("server", "check_session_iframe");
		const baseUrl = this.env.getString("base_url");
		const rpSessionIframeUrl = baseUrl + (firstTime ? "/rp_session_iframe" : "/second_rp_session_iframe");

		await this.setStatus(Status.WAITING);

		return modelAndView("sessionVerify", {
			check_session_iframe: checkSessionIframeUrl,
			session_iframe_unchanged: rpSessionIframeUrl,
		});
	}

	protected async handleRpSessionIframe(_requestParts: JsonObject, firstTime: boolean): Promise<Response> {
		await this.setStatus(Status.RUNNING);

		const clientId = this.env.getString("client", "client_id");
		const sessionState = this.env.getString("session_state");
		const issuer = this.env.getString("server", "issuer");
		let sessionResultUrl: string;
		if (firstTime) {
			sessionResultUrl = this.env.getString("base_url") + "/session_result";
		} else {
			sessionResultUrl = this.env.getString("base_url") + "/second_session_result";
		}

		await this.setStatus(Status.WAITING);

		return modelAndView("rpSessionIframe", {
			client_id: clientId,
			session_state: sessionState,
			issuer: issuer,
			service_url: sessionResultUrl,
		});
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

import { AddFrontchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest } from "../condition/client/AddFrontchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest.ts";
import { AddFrontchannelLogoutUriToDynamicRegistrationRequest } from "../condition/client/AddFrontchannelLogoutUriToDynamicRegistrationRequest.ts";
import { CheckForUnexpectedParametersInFrontchannelLogoutRequest } from "../condition/client/CheckForUnexpectedParametersInFrontchannelLogoutRequest.ts";
import { CheckForUnexpectedParametersInPostLogoutRedirect } from "../condition/client/CheckForUnexpectedParametersInPostLogoutRedirect.ts";
import { CheckIdTokenSidMatchesFrontChannelLogoutRequest } from "../condition/client/CheckIdTokenSidMatchesFrontChannelLogoutRequest.ts";
import { CheckPostLogoutState } from "../condition/client/CheckPostLogoutState.ts";
import { CreateFrontchannelLogoutUri } from "../condition/client/CreateFrontchannelLogoutUri.ts";
import { ValidateFrontchannelLogoutIss } from "../condition/client/ValidateFrontchannelLogoutIss.ts";
import {
	args,
	ConditionResult,
	modelAndView,
	responseEntity,
	Status,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonObject,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCRpInitiatedLogout } from "./AbstractOIDCCRpInitiatedLogout.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_FrontChannel_RpInitLogout
// https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-FrontChannel-RpInitLogout.json
export class OIDCCFrontChannelRpInitiatedLogout extends AbstractOIDCCRpInitiatedLogout {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-frontchannel-rp-initiated-logout",
		displayName: "OIDCC: Frontchannel rp initiated logout",
		summary:
			"This test performs a normal authorization flow at the OP, then sends the user to the end_session_endpoint. It validates the OP correctly loads the frontchannel_logout_uri and sends the user to the post_logout_redirect_uri, then tries another authentication with prompt=none which must return an error (as the user has been logged out).\n\nIf using static client registration you must register frontchannel_logout_uri to the same url as the redirect url, but replacing the portion after the alias with /frontchannel_logout and similarly register /post_logout_redirect as a post_logout_redirect_uri.",
		profile: "OIDCC",
	};

	private postLogoutRedirectRequestParts: JsonObject | null = null;
	private frontchannelLogoutRequestParts: JsonObject | null = null;

	protected override async configureClient(): Promise<void> {
		await this.callAndStopOnFailure(CreateFrontchannelLogoutUri, "OIDCFCL-2");
		await super.configureClient();
	}

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		await this.callAndStopOnFailure(AddFrontchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest, "OIDCFCL-2");
		await this.callAndStopOnFailure(AddFrontchannelLogoutUriToDynamicRegistrationRequest, "OIDCFCL-2");
	}

	protected async validateLogoutResults(): Promise<void> {
		const fcLogoutEnvKey = "frontchannel_logout_request";
		this.env.putObject("post_logout_redirect", this.postLogoutRedirectRequestParts);
		this.env.putObject(fcLogoutEnvKey, this.frontchannelLogoutRequestParts);

		this.eventLog.startBlock("Verify frontchannel logout request");
		this.env.mapKey("client_request", fcLogoutEnvKey);
		await this.callAndContinueOnFailure(
			CheckForUnexpectedParametersInFrontchannelLogoutRequest,
			ConditionResult.WARNING,
			"OIDCFCL-2",
		);
		await this.callAndContinueOnFailure(ValidateFrontchannelLogoutIss, ConditionResult.FAILURE, "OIDCFCL-2");
		await this.callAndContinueOnFailure(
			CheckIdTokenSidMatchesFrontChannelLogoutRequest,
			ConditionResult.FAILURE,
			"OIDCFCL-2",
			"OIDCFCL-3",
		);
		this.env.unmapKey("client_request");
		this.eventLog.endBlock();

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
		if (path === "frontchannel_logout") {
			return this.handleFrontchannelLogout(requestParts);
		} else if (path === "post_logout_redirect") {
			return this.handlePostLogoutRedirect(requestParts);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	protected async handlePostLogoutRedirect(requestParts: JsonObject): Promise<Response> {
		await this.setStatus(Status.RUNNING);
		this.postLogoutRedirectRequestParts = requestParts;
		if (this.frontchannelLogoutRequestParts == null) {
			this.eventLog.log(
				this.getName(),
				args("msg", "Received front channel redirect; waiting for front channel request"),
			);
		} else {
			this.validateLogoutResultsInBackground();
		}
		await this.setStatus(Status.WAITING);

		return modelAndView("resultCaptured", {
			returnUrl: "/log-detail.html?log=" + this.getId(),
		});
	}

	protected async handleFrontchannelLogout(requestParts: JsonObject): Promise<Response> {
		await this.setStatus(Status.RUNNING);
		this.frontchannelLogoutRequestParts = requestParts;
		if (this.postLogoutRedirectRequestParts == null) {
			this.eventLog.log(
				this.getName(),
				args("msg", "Received frontchannel request; waiting for front channel redirect"),
			);
		} else {
			this.validateLogoutResultsInBackground();
		}
		await this.setStatus(Status.WAITING);

		// https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
		return responseEntity("", 200, { "Cache-Control": "no-store" });
	}

	private validateLogoutResultsInBackground(): void {
		this.getTestExecutionManager().runInBackground(async () => {
			await this.setStatus(Status.RUNNING);
			await this.validateLogoutResults();
			return "done";
		});
	}
}

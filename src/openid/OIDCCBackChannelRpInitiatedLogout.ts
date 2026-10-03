import { AddBackchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest } from "../condition/client/AddBackchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest.ts";
import { AddBackchannelLogoutUriToDynamicRegistrationRequest } from "../condition/client/AddBackchannelLogoutUriToDynamicRegistrationRequest.ts";
import { CheckForUnexpectedParametersInBackchannelLogoutRequest } from "../condition/client/CheckForUnexpectedParametersInBackchannelLogoutRequest.ts";
import { CheckForUnexpectedParametersInPostLogoutRedirect } from "../condition/client/CheckForUnexpectedParametersInPostLogoutRedirect.ts";
import { CheckIdTokenSidMatchesLogoutToken } from "../condition/client/CheckIdTokenSidMatchesLogoutToken.ts";
import { CheckIdTokenSubMatchesLogoutToken } from "../condition/client/CheckIdTokenSubMatchesLogoutToken.ts";
import { CheckLogoutTokenHasSubOrSid } from "../condition/client/CheckLogoutTokenHasSubOrSid.ts";
import { CheckLogoutTokenNoNonce } from "../condition/client/CheckLogoutTokenNoNonce.ts";
import { CheckPostLogoutState } from "../condition/client/CheckPostLogoutState.ts";
import { CreateBackchannelLogoutUri } from "../condition/client/CreateBackchannelLogoutUri.ts";
import { ExtractLogoutTokenFromBackchannelLogoutRequest } from "../condition/client/ExtractLogoutTokenFromBackchannelLogoutRequest.ts";
import { ValidateLogoutTokenClaims } from "../condition/client/ValidateLogoutTokenClaims.ts";
import { ValidateLogoutTokenFromBackchannelLogoutRequestEncryption } from "../condition/client/ValidateLogoutTokenFromBackchannelLogoutRequestEncryption.ts";
import { ValidateLogoutTokenSignature } from "../condition/client/ValidateLogoutTokenSignature.ts";
import { EnsureIncomingTls12WithSecureCipherOrTls13 } from "../condition/common/EnsureIncomingTls12WithSecureCipherOrTls13.ts";
import { EnsureIncomingTls13 } from "../condition/common/EnsureIncomingTls13.ts";
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

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_BackChannel_RpInitLogout
// https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-BackChannel-RpInitLogout.json
export class OIDCCBackChannelRpInitiatedLogout extends AbstractOIDCCRpInitiatedLogout {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-backchannel-rp-initiated-logout",
		displayName: "OIDCC: Backchannel rp initiated logout",
		summary:
			"This test performs a normal authorization flow at the OP, then sends the user to the end_session_endpoint. It validates the OP correctly calls the backchannel_logout_uri and sends the user to the post_logout_redirect_uri, then tries another authentication with prompt=none which must return an error (as the user has been logged out).\n\nIf using static client registration you must register backchannel_logout_uri to the same url as the redirect url, but replacing the portion after the alias with /backchannel_logout and similarly register /post_logout_redirect as a post_logout_redirect_uri.",
		profile: "OIDCC",
	};

	private postLogoutRedirectRequestParts: JsonObject | null = null;
	private backchannelLogoutRequestParts: JsonObject | null = null;

	protected override async configureClient(): Promise<void> {
		await this.callAndStopOnFailure(CreateBackchannelLogoutUri, "OIDCBCL-2.2");
		await super.configureClient();
	}

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		await this.callAndStopOnFailure(AddBackchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest, "OIDCBCL-2.2");
		await this.callAndStopOnFailure(AddBackchannelLogoutUriToDynamicRegistrationRequest, "OIDCBCL-2.2");
	}

	protected async validateLogoutResults(): Promise<void> {
		const bcLogoutEnvKey = "backchannel_logout_request";
		this.env.putObject("post_logout_redirect", this.postLogoutRedirectRequestParts);
		this.env.putObject(bcLogoutEnvKey, this.backchannelLogoutRequestParts);

		this.eventLog.startBlock("Verify backchannel logout request");
		this.env.mapKey("client_request", bcLogoutEnvKey);
		// This is a mixture of must & recommended in BCP195, but BCP195 is not a normative reference of OIDCC so only raise a warning
		await this.callAndContinueOnFailure(
			EnsureIncomingTls12WithSecureCipherOrTls13,
			ConditionResult.WARNING,
			"BCP195-3.1.1",
		);
		await this.callAndContinueOnFailure(EnsureIncomingTls13, ConditionResult.WARNING, "RFC9325-3.1.1");
		await this.skipIfMissing(
			["client_jwks"],
			null,
			ConditionResult.INFO,
			ValidateLogoutTokenFromBackchannelLogoutRequestEncryption,
			ConditionResult.WARNING,
			"OIDCBCL-2.4",
		);
		await this.callAndStopOnFailure(ExtractLogoutTokenFromBackchannelLogoutRequest, "OIDCBCL-2.5");
		await this.callAndContinueOnFailure(
			CheckForUnexpectedParametersInBackchannelLogoutRequest,
			ConditionResult.WARNING,
			"OIDCBCL-2.5",
		);
		await this.callAndContinueOnFailure(ValidateLogoutTokenSignature, ConditionResult.FAILURE, "OIDCBCL-2.4");
		await this.callAndContinueOnFailure(ValidateLogoutTokenClaims, ConditionResult.FAILURE, "OIDCBCL-2.4");
		await this.skipIfElementMissing(
			"logout_token",
			"claims.sub",
			ConditionResult.INFO,
			CheckIdTokenSubMatchesLogoutToken,
			ConditionResult.FAILURE,
			"OIDCBCL-2.4",
		);
		await this.skipIfElementMissing(
			"logout_token",
			"claims.sid",
			ConditionResult.INFO,
			CheckIdTokenSidMatchesLogoutToken,
			ConditionResult.FAILURE,
			"OIDCBCL-2.4",
		);
		await this.callAndContinueOnFailure(CheckLogoutTokenNoNonce, ConditionResult.FAILURE, "OIDCBCL-2.4");
		await this.callAndContinueOnFailure(CheckLogoutTokenHasSubOrSid, ConditionResult.FAILURE, "OIDCBCL-2.4");
		this.env.unmapKey("client_request");
		this.eventLog.endBlock();

		this.eventLog.startBlock("Verify frontchannel post logout redirect");
		await this.callAndContinueOnFailure(CheckPostLogoutState, ConditionResult.FAILURE, "OIDCRIL-2");
		await this.callAndContinueOnFailure(
			CheckForUnexpectedParametersInPostLogoutRedirect,
			ConditionResult.WARNING,
			"OIDCRIL-3",
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
		if (path === "backchannel_logout") {
			return this.handleBackchannelLogout(requestParts);
		} else if (path === "post_logout_redirect") {
			return this.handlePostLogoutRedirect(requestParts);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	protected async handlePostLogoutRedirect(requestParts: JsonObject): Promise<Response> {
		await this.setStatus(Status.RUNNING);
		this.postLogoutRedirectRequestParts = requestParts;
		if (this.backchannelLogoutRequestParts == null) {
			this.eventLog.log(
				this.getName(),
				args("msg", "Received front channel redirect; waiting for back channel request"),
			);
		} else {
			this.validateLogoutResultsInBackground();
		}
		await this.setStatus(Status.WAITING);

		return modelAndView("resultCaptured", {
			returnUrl: "/log-detail.html?log=" + this.getId(),
		});
	}

	protected async handleBackchannelLogout(requestParts: JsonObject): Promise<Response> {
		await this.setStatus(Status.RUNNING);
		this.backchannelLogoutRequestParts = requestParts;
		if (this.postLogoutRedirectRequestParts == null) {
			this.eventLog.log(
				this.getName(),
				args("msg", "Received backchannel request; waiting for front channel redirect"),
			);
		} else {
			this.validateLogoutResultsInBackground();
		}
		await this.setStatus(Status.WAITING);

		// as per https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse
		// we always return a successful response as this test expects a valid request
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

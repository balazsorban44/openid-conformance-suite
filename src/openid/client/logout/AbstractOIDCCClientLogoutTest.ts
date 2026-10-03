import {
	ConditionResult,
	TestFailureException,
	jsonResponse,
	modelAndView,
	redirectView,
	type JsonObject,
	type ModuleVariantMetadata,
} from "../../../framework/index.ts";
import { OIDCCGenerateServerConfigurationWithSessionManagement } from "../../../condition/as/OIDCCGenerateServerConfigurationWithSessionManagement.ts";
import { AddSessionStateToAuthorizationEndpointResponseParams } from "../../../condition/as/logout/AddSessionStateToAuthorizationEndpointResponseParams.ts";
import { AddSidToIdTokenClaims } from "../../../condition/as/logout/AddSidToIdTokenClaims.ts";
import { CallRPBackChannelLogoutEndpoint } from "../../../condition/as/logout/CallRPBackChannelLogoutEndpoint.ts";
import { CreatePostLogoutRedirectUriParams } from "../../../condition/as/logout/CreatePostLogoutRedirectUriParams.ts";
import { CreatePostLogoutRedirectUriRedirect } from "../../../condition/as/logout/CreatePostLogoutRedirectUriRedirect.ts";
import { CreateRPFrontChannelLogoutRequestUrl } from "../../../condition/as/logout/CreateRPFrontChannelLogoutRequestUrl.ts";
import { EncryptLogoutToken } from "../../../condition/as/logout/EncryptLogoutToken.ts";
import { EnsureBackChannelLogoutEndpointResponseContainsCacheHeaders } from "../../../condition/as/logout/EnsureBackChannelLogoutEndpointResponseContainsCacheHeaders.ts";
import { EnsureClientHasBackChannelLogoutUri } from "../../../condition/as/logout/EnsureClientHasBackChannelLogoutUri.ts";
import { EnsureClientHasFrontChannelLogoutUri } from "../../../condition/as/logout/EnsureClientHasFrontChannelLogoutUri.ts";
import { GenerateLogoutTokenClaims } from "../../../condition/as/logout/GenerateLogoutTokenClaims.ts";
import { GenerateSessionState } from "../../../condition/as/logout/GenerateSessionState.ts";
import { LogCheckSessionIframeRequest } from "../../../condition/as/logout/LogCheckSessionIframeRequest.ts";
import { LogGetSessionStateRequest } from "../../../condition/as/logout/LogGetSessionStateRequest.ts";
import { LogoutByRemovingSessionState } from "../../../condition/as/logout/LogoutByRemovingSessionState.ts";
import { OIDCCSignLogoutToken } from "../../../condition/as/logout/OIDCCSignLogoutToken.ts";
import { ValidateIdTokenHintInRPInitiatedLogoutRequest } from "../../../condition/as/logout/ValidateIdTokenHintInRPInitiatedLogoutRequest.ts";
import { ValidatePostLogoutRedirectUri } from "../../../condition/as/logout/ValidatePostLogoutRedirectUri.ts";
import { ClientRegistration } from "../../../variant/ClientRegistration.ts";
import { AbstractOIDCCClientTest } from "../AbstractOIDCCClientTest.ts";
import "../../../framework/views/checkSessionIFrame.ts";
import "../../../framework/views/oidccFrontChannelLogout.ts";

/**
 * Port of org.apache.commons.text.StringEscapeUtils.escapeEcmaScript: escapes ' " \ / with a backslash,
 * the Java control characters as \b \n \t \f \r, and every other char outside 32..0x7f as \\uXXXX
 * (upper case hex, UTF-16 code units).
 */
function escapeEcmaScript(input: string | null): string | null {
	if (input == null) {
		return null;
	}
	let out = "";
	for (let i = 0; i < input.length; i++) {
		const c = input.charAt(i);
		const code = input.charCodeAt(i);
		switch (c) {
			case "'":
			case '"':
			case "\\":
			case "/":
				out += "\\" + c;
				continue;
			case "\b":
				out += "\\b";
				continue;
			case "\n":
				out += "\\n";
				continue;
			case "\t":
				out += "\\t";
				continue;
			case "\f":
				out += "\\f";
				continue;
			case "\r":
				out += "\\r";
				continue;
			default:
				break;
		}
		if (code < 32 || code > 0x7f) {
			out += "\\u" + code.toString(16).toUpperCase().padStart(4, "0");
		} else {
			out += c;
		}
	}
	return out;
}

// Java: not declared abstract, but has no @PublishTestModule
export class AbstractOIDCCClientLogoutTest extends AbstractOIDCCClientTest {
	// @VariantConfigurationFields(parameter = ClientRegistration.class, value = "static_client", configurationFields = {...})
	static override variants: ModuleVariantMetadata = {
		configurationFields: [
			{
				parameter: ClientRegistration,
				value: "static_client",
				configurationFields: ["client.post_logout_redirect_uri"],
			},
		],
	};

	protected receivedCheckSessionRequestBeforeLogout = false;
	protected receivedEndSessionRequest = false;
	protected receivedCheckSessionRequestAfterLogout = false;
	protected sentBackChannelLogoutRequest = false;
	protected receivedFrontChannelLogoutCompletedCallback = false;

	protected override async configureServerConfiguration(): Promise<void> {
		await this.callAndStopOnFailure(
			OIDCCGenerateServerConfigurationWithSessionManagement,
			"OIDCBCL-2.1",
			"OIDCSM-3.3",
			"OIDCFCL-3",
			"OIDCRIL-2.1",
		);
		this.expose("end_session_endpoint", this.env.getString("base_url") + "/end_session_endpoint");
	}

	protected override async validateAuthorizationEndpointRequestParameters(): Promise<void> {
		await super.validateAuthorizationEndpointRequestParameters();
		await this.callAndStopOnFailure(GenerateSessionState, "OIDCSM-3");
	}

	protected override async addCustomValuesToIdToken(): Promise<void> {
		await super.addCustomValuesToIdToken();
		await this.callAndStopOnFailure(AddSidToIdTokenClaims, "OIDCFCL-3");
	}

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		if (this.receivedAuthorizationRequest && this.receivedEndSessionRequest) {
			await this.fireTestFinished();
			return true;
		}
		return false;
	}

	protected override async handleClientRequestForPath(
		requestId: string,
		path: string,
		servletResponse: unknown,
	): Promise<Response> {
		if ("check_session_iframe" === path) {
			return this.handleCheckSessionIFrameRequest(requestId, servletResponse);
		} else if ("end_session_endpoint" === path) {
			return this.handleEndSessionEndpointRequest(requestId);
		} else if ("get_session_state" === path) {
			return this.handleGetSessionStateViaAjaxRequest(requestId);
		} else if ("frontchannel_logout_handler" === path) {
			return this.createFrontChannelLogoutModelAndView(true);
		} else if ("frontchannel_logout_callback" === path) {
			return this.handleFrontChannelLogoutCallbackHandler(requestId, path, servletResponse);
		} else {
			return super.handleClientRequestForPath(requestId, path, servletResponse);
		}
	}

	/**
	 * session_state
	 * Session State. JSON [RFC7159] string that represents the End-User's login state at the OP.
	 * It MUST NOT contain the space (" ") character. This value is opaque to the RP.
	 * This is REQUIRED if session management is supported.
	 */
	protected override async customizeAuthorizationEndpointResponseParams(): Promise<void> {
		await this.callAndStopOnFailure(AddSessionStateToAuthorizationEndpointResponseParams, "OIDCSM-3");
	}

	/**
	 * The check session iframe does not calculate session_state itself, it just sends an ajax request
	 * to check_session_ajax_url which is used to track test progress state
	 *
	 * @param requestId
	 * @param servletResponse
	 * @return
	 */
	protected async handleCheckSessionIFrameRequest(_requestId: string, _servletResponse: unknown): Promise<Response> {
		await this.call(this.exec().startBlock("check_session_iframe requested"));

		await this.callAndStopOnFailure(LogCheckSessionIframeRequest);

		await this.call(this.exec().endBlock());
		return modelAndView("checkSessionIFrame", {
			check_session_ajax_url: this.env.getString("base_url") + "/get_session_state",
		});
	}

	protected async handleEndSessionEndpointRequest(requestId: string): Promise<Response> {
		this.receivedEndSessionRequest = true;
		await this.call(
			this.exec().startBlock("End session endpoint").mapKey("end_session_endpoint_http_request", requestId),
		);

		this.setEndSessionEndpointRequestParamsSource();

		await this.validateEndSessionEndpointParameters();

		await this.createPostLogoutUriRedirect();

		const viewToReturn = await this.createEndSessionEndpointResponse();

		await this.removeSessionState();

		return viewToReturn;
	}

	protected setEndSessionEndpointRequestParamsSource(): void {
		const httpMethod = this.env.getString("end_session_endpoint_http_request", "method");
		const httpRequestObj = this.env.getObject("end_session_endpoint_http_request") as JsonObject;

		//the spec does not restrict it to GET or POST only
		if ("POST" === httpMethod) {
			this.env.putObject(
				"end_session_endpoint_http_request_params",
				(httpRequestObj["body_form_params"] as JsonObject | undefined) ?? null,
			);
		} else if ("GET" === httpMethod) {
			this.env.putObject(
				"end_session_endpoint_http_request_params",
				(httpRequestObj["query_string_params"] as JsonObject | undefined) ?? null,
			);
		} else {
			//this should not happen?
			throw new TestFailureException(this.getId(), "Got unexpected HTTP method to end session endpoint");
		}
	}

	protected async removeSessionState(): Promise<void> {
		await this.callAndStopOnFailure(LogoutByRemovingSessionState);
	}

	protected async createPostLogoutUriRedirect(): Promise<void> {
		await this.callAndStopOnFailure(CreatePostLogoutRedirectUriParams, "OIDCRIL-3");

		await this.customizeEndSessionEndpointResponseParameters();

		await this.callAndStopOnFailure(CreatePostLogoutRedirectUriRedirect, "OIDCRIL-3");
	}

	/**
	 * Returns a redirect to post_logout_redirect_uri
	 * @return
	 */
	protected async createEndSessionEndpointResponse(): Promise<Response> {
		const redirectTo = this.env.getString("post_logout_redirect_uri_redirect") as string;

		return redirectView(redirectTo);
	}
	/**
	 * Called before the end session endpoint response redirect url is created.
	 * No-op by default, override in child classes to change behavior.
	 */
	protected async customizeEndSessionEndpointResponseParameters(): Promise<void> {}

	/**
	 * If you override, you will probably want to call super.validateEndSessionEndpointParameters()
	 */
	protected async validateEndSessionEndpointParameters(): Promise<void> {
		await this.callAndContinueOnFailure(
			ValidateIdTokenHintInRPInitiatedLogoutRequest,
			ConditionResult.FAILURE,
			"OIDCRIL-2",
		);
		await this.callAndContinueOnFailure(ValidatePostLogoutRedirectUri, ConditionResult.FAILURE, "OIDCRIL-3.1");
	}
	/**
	 * Called from the check_session_iframe receiveMessage method via ajax
	 * Used to verify that the check_session_iframe received messages via postMessage
	 * Returns session_state_data from env
	 * @param requestId
	 * @return
	 */
	protected async handleGetSessionStateViaAjaxRequest(requestId: string): Promise<Response> {
		await this.call(
			this.exec().startBlock("Get session state - postMessage callback").mapKey("incoming_request", requestId),
		);

		if (this.receivedEndSessionRequest) {
			this.receivedCheckSessionRequestAfterLogout = true;
		} else {
			this.receivedCheckSessionRequestBeforeLogout = true;
		}
		const headers = { "content-type": "application/json" };
		const body = this.env.getObject("session_state_data");

		await this.callAndStopOnFailure(LogGetSessionStateRequest);

		await this.call(this.exec().unmapKey("incoming_request").endBlock());
		if (body != null) {
			return jsonResponse(body, 200, headers);
		} else {
			return jsonResponse({}, 200, headers);
		}
	}

	protected async createLogoutToken(): Promise<void> {
		await this.call(this.exec().startBlock("Create Logout Token"));
		await this.generateLogoutTokenClaims();
		await this.customizeLogoutTokenClaims();

		await this.signLogoutToken();

		await this.customizeLogoutTokenSignature();

		await this.encryptLogoutTokenIfNecessary();
		await this.call(this.exec().endBlock());
	}

	protected async generateLogoutTokenClaims(): Promise<void> {
		await this.callAndContinueOnFailure(GenerateLogoutTokenClaims, ConditionResult.FAILURE, "OIDCBCL-2.4");
	}

	protected async sendBackChannelLogoutRequest(): Promise<void> {
		await this.call(this.exec().startBlock("Send Back Channel Logout Request"));
		await this.callAndContinueOnFailure(EnsureClientHasBackChannelLogoutUri, ConditionResult.FAILURE, "OIDCBCL-2.2");
		await this.callAndContinueOnFailure(CallRPBackChannelLogoutEndpoint, ConditionResult.FAILURE, "OIDCBCL-2.5");
		await this.validateBackChannelLogoutResponse();
		await this.call(this.exec().endBlock());
		this.sentBackChannelLogoutRequest = true;
	}

	protected async validateBackChannelLogoutResponse(): Promise<void> {
		await this.callAndContinueOnFailure(
			EnsureBackChannelLogoutEndpointResponseContainsCacheHeaders,
			ConditionResult.WARNING,
			"OIDCBCL-2.8",
		);
	}

	/**
	 * Override to modify logout token claims
	 * Called right after generateLogoutTokenClaims
	 */
	protected async customizeLogoutTokenClaims(): Promise<void> {}

	protected async customizeLogoutTokenSignature(): Promise<void> {}

	protected async signLogoutToken(): Promise<void> {
		await this.callAndContinueOnFailure(OIDCCSignLogoutToken, ConditionResult.FAILURE, "OIDCBCL-2.4");
	}

	protected async encryptLogoutTokenIfNecessary(): Promise<void> {
		await this.skipIfElementMissing(
			"client",
			"id_token_encrypted_response_alg",
			ConditionResult.INFO,
			EncryptLogoutToken,
			ConditionResult.FAILURE,
			"OIDCBCL-2.4",
			"OIDCC-10.2",
		);
	}

	// since it's a cross domain request we can't know if the page actually loaded or not.
	// iframe onload event gets triggered even when loading the url actually fails,
	// due to for example an x-frame-options restriction.
	// That's why fireTestReviewNeeded is called
	protected async handleFrontChannelLogoutCallbackHandler(
		_requestId: string,
		_path: string,
		_servletResponse: unknown,
	): Promise<Response> {
		await this.call(this.exec().startBlock("Front Channel Logout Ajax Callback Handler Request"));
		await this.call(this.exec().endBlock());
		this.receivedFrontChannelLogoutCompletedCallback = true;
		this.fireTestReviewNeeded();
		const response: JsonObject = {};
		response["ok"] = true;
		return jsonResponse(response, 200);
	}

	protected async createFrontChannelLogoutModelAndView(isOPinit: boolean): Promise<Response> {
		await this.call(this.exec().startBlock("Render Page With Front Channel Logout Iframe"));
		await this.call(this.exec().endBlock());
		//'OPINIT' value is used in the template(templates/oidccFrontChannelLogout.html) to check if it's OP init or not
		let postLogoutRedir: string | null = "OPINIT";
		if (!isOPinit) {
			postLogoutRedir = this.env.getString("post_logout_redirect_uri_redirect");
		}
		return modelAndView("oidccFrontChannelLogout", {
			rp_frontchannel_logout_uri: escapeEcmaScript(this.env.getString("rp_frontchannel_logout_uri_request_url")),
			iframe_loaded_callback_url: this.env.getString("base_url") + "/frontchannel_logout_callback",
			post_logout_redirect_uri_redirect: postLogoutRedir,
		});
	}

	protected async createFrontChannelLogoutRequestUrl(): Promise<void> {
		await this.call(this.exec().startBlock("Create Front Channel Logout Request"));
		await this.callAndContinueOnFailure(EnsureClientHasFrontChannelLogoutUri, ConditionResult.FAILURE, "OIDCFCL-2");
		await this.callAndStopOnFailure(CreateRPFrontChannelLogoutRequestUrl, "OIDCFCL-2");
		await this.call(this.exec().endBlock());
	}
}

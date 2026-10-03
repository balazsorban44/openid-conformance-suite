import type { ModuleVariantMetadata, PublishTestModule } from "../../../framework/index.ts";
import { EnsureClientHasAtLeastOneOfBackOrFrontChannelLogoutUri } from "../../../condition/as/logout/EnsureClientHasAtLeastOneOfBackOrFrontChannelLogoutUri.ts";
import { ClientRegistration } from "../../../variant/ClientRegistration.ts";
import { AbstractOIDCCClientLogoutTest } from "./AbstractOIDCCClientLogoutTest.ts";

/*
 * OIDCCClientTestRPInitLogoutInvalidState and OIDCCClientTestRPInitLogoutNoState extend this class
 * don't forget to update them if you modify this class
 *
 * This test (and tests extending this one) sends both back channel and front channel logout requests
 * at the same time if both endpoints are defined.
 * Python tests were doing the same and confirmed by Filip that this is intended behavior.
 *
 */
export class OIDCCClientTestRPInitLogout extends AbstractOIDCCClientLogoutTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-rp-init-logout",
		displayName: "OIDCC: Relying party test, RP initiated logout.",
		summary:
			"The client is expected to make an authorization request " +
			"(also a token request and a optionally a userinfo request when applicable)," +
			" then terminate the session by calling the end_session_endpoint (RP-Initiated Logout)," +
			" at this point the conformance suite will " +
			" send a back channel logout request to the RP if only backchannel_logout_uri is set" +
			" or will send a front channel logout request to the RP if only frontchannel_logout_uri is set" +
			" or will send both front and back channel logout requests" +
			" if both backchannel_logout_uri and frontchannel_logout_uri are set," +
			" then the RP is expected to handle post logout URI redirect." +
			" Corresponds to rp-init-logout in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	// @VariantConfigurationFields(parameter = ClientRegistration.class, value = "static_client", configurationFields = {...})
	static override variants: ModuleVariantMetadata = {
		configurationFields: [
			{
				parameter: ClientRegistration,
				value: "static_client",
				configurationFields: ["client.backchannel_logout_uri", "client.frontchannel_logout_uri"],
			},
		],
	};

	protected clientHasBackChannelLogoutUri = false;
	protected clientHasFrontChannelLogoutUri = false;

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		if (this.receivedAuthorizationRequest && this.receivedEndSessionRequest) {
			if (this.clientHasBackChannelLogoutUri && this.clientHasFrontChannelLogoutUri) {
				if (this.receivedFrontChannelLogoutCompletedCallback && this.sentBackChannelLogoutRequest) {
					await this.fireTestFinished();
					return true;
				}
			} else if (this.clientHasBackChannelLogoutUri) {
				if (this.sentBackChannelLogoutRequest) {
					await this.fireTestFinished();
					return true;
				}
			} else if (this.clientHasFrontChannelLogoutUri) {
				if (this.receivedFrontChannelLogoutCompletedCallback) {
					await this.fireTestFinished();
					return true;
				}
			}
		}
		return false;
	}

	protected override async handleEndSessionEndpointRequest(requestId: string): Promise<Response> {
		this.receivedEndSessionRequest = true;
		await this.callAndStopOnFailure(EnsureClientHasAtLeastOneOfBackOrFrontChannelLogoutUri);
		this.clientHasFrontChannelLogoutUri = !!this.env.getString("client", "frontchannel_logout_uri");
		this.clientHasBackChannelLogoutUri = !!this.env.getString("client", "backchannel_logout_uri");
		if (this.clientHasBackChannelLogoutUri) {
			//this must be created before the session is actually removed from env
			await this.createLogoutToken();
		}
		const viewToReturn = await super.handleEndSessionEndpointRequest(requestId);
		if (this.clientHasBackChannelLogoutUri) {
			await this.sendBackChannelLogoutRequest();
		}
		return viewToReturn;
	}

	protected override async createEndSessionEndpointResponse(): Promise<Response> {
		if (this.clientHasFrontChannelLogoutUri) {
			await this.createFrontChannelLogoutRequestUrl();
			return this.createFrontChannelLogoutModelAndView(false);
		} else {
			return super.createEndSessionEndpointResponse();
		}
	}

	protected skipTestIfStateIsOmitted(): void {
		const state = this.env.getString("end_session_endpoint_http_request_params", "state");
		if (!state) {
			this.fireTestSkipped(
				"Skipping test due to the optional state parameter not being supplied to the end_session_endpoint",
			);
		}
	}
}

import type { ModuleVariantMetadata } from "../../../framework/index.ts";
import { ClientRegistration } from "../../../variant/ClientRegistration.ts";
import { AbstractOIDCCClientLogoutTest } from "./AbstractOIDCCClientLogoutTest.ts";

export abstract class AbstractOIDCCClientBackChannelLogoutTest extends AbstractOIDCCClientLogoutTest {
	// @VariantConfigurationFields(parameter = ClientRegistration.class, value = "static_client", configurationFields = {...})
	static override variants: ModuleVariantMetadata = {
		configurationFields: [
			{
				parameter: ClientRegistration,
				value: "static_client",
				configurationFields: ["client.backchannel_logout_uri"],
			},
		],
	};

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		if (this.receivedAuthorizationRequest && this.receivedEndSessionRequest && this.sentBackChannelLogoutRequest) {
			await this.fireTestFinished();
			return true;
		}
		return false;
	}

	protected override async handleEndSessionEndpointRequest(requestId: string): Promise<Response> {
		//this must be created before the session is actually removed from env
		await this.createLogoutToken();
		const viewToReturn = await super.handleEndSessionEndpointRequest(requestId);
		await this.sendBackChannelLogoutRequest();
		return viewToReturn;
	}
}

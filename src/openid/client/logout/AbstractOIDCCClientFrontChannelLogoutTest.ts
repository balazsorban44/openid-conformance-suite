import type { ModuleVariantMetadata } from "../../../framework/index.ts";
import { ClientRegistration } from "../../../variant/ClientRegistration.ts";
import { AbstractOIDCCClientLogoutTest } from "./AbstractOIDCCClientLogoutTest.ts";

export abstract class AbstractOIDCCClientFrontChannelLogoutTest extends AbstractOIDCCClientLogoutTest {
	// @VariantConfigurationFields(parameter = ClientRegistration.class, value = "static_client", configurationFields = {...})
	static override variants: ModuleVariantMetadata = {
		configurationFields: [
			{
				parameter: ClientRegistration,
				value: "static_client",
				configurationFields: ["client.frontchannel_logout_uri"],
			},
		],
	};

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		if (this.receivedAuthorizationRequest && this.receivedFrontChannelLogoutCompletedCallback) {
			await this.fireTestFinished();
			return true;
		}
		return false;
	}

	protected override async createEndSessionEndpointResponse(): Promise<Response> {
		await this.createFrontChannelLogoutRequestUrl();
		return this.createFrontChannelLogoutModelAndView(false);
	}
}

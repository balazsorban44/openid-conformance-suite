import { AddInitiateLoginUriToDynamicRegistrationRequest } from "../condition/client/AddInitiateLoginUriToDynamicRegistrationRequest.ts";
import { CallClientConfigurationEndpoint } from "../condition/client/CallClientConfigurationEndpoint.ts";
import { CheckRegistrationClientEndpointContentType } from "../condition/client/CheckRegistrationClientEndpointContentType.ts";
import { CheckRegistrationClientEndpointContentTypeHttpStatus200 } from "../condition/client/CheckRegistrationClientEndpointContentTypeHttpStatus200.ts";
import { CreateInitiateLoginUri } from "../condition/client/CreateInitiateLoginUri.ts";
import { ValidateInitiateLoginUriInConfigurationResponse } from "../condition/client/ValidateInitiateLoginUriInConfigurationResponse.ts";
import { ValidateInitiateLoginUriInRegistrationResponse } from "../condition/client/ValidateInitiateLoginUriInRegistrationResponse.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ConditionResult, type ModuleVariantMetadata, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to OP-3rd_party-init-login
// https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_3rd_party_init_login
export class OIDCC3rdPartyInitLogin extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-3rd_party-init-login",
		displayName: "OIDCC: 3rd party initiated login",
		summary:
			"Registers a client including the 'initiate_login_uri' parameter, and verifies that the response includes the initiate_login_uri and that it is returned from the client management endpoint ('registration_client_uri' returned by the OP).",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		await this.callAndStopOnFailure(CreateInitiateLoginUri, "OIDCC-4", "OIDCR-2");
		await this.callAndStopOnFailure(AddInitiateLoginUriToDynamicRegistrationRequest, "OIDCC-4", "OIDCR-2");
	}

	protected override async performAuthorizationFlow(): Promise<void> {
		await this.callAndContinueOnFailure(
			ValidateInitiateLoginUriInRegistrationResponse,
			ConditionResult.FAILURE,
			"OIDCR-3.2",
		);

		this.eventLog.startBlock("Call client configuration endpoint");
		// The python test called the client configuration endpoint. I'm not convinced it's a mandatory to implement
		// feature for this profile, but we just do as the python test did.
		await this.callAndStopOnFailure(CallClientConfigurationEndpoint, "OIDCD-4.2");
		await this.callAndContinueOnFailure(
			CheckRegistrationClientEndpointContentTypeHttpStatus200,
			ConditionResult.FAILURE,
			"OIDCD-4.3",
		);
		await this.callAndContinueOnFailure(
			CheckRegistrationClientEndpointContentType,
			ConditionResult.FAILURE,
			"OIDCD-4.3",
		);
		await this.callAndContinueOnFailure(
			ValidateInitiateLoginUriInConfigurationResponse,
			ConditionResult.FAILURE,
			"OIDCD-4.3",
		);
		this.eventLog.endBlock();

		await this.fireTestFinished();
	}
}

import { AddInitiateLoginUriAsNonHttpsToDynamicRegistrationRequest } from "../condition/client/AddInitiateLoginUriAsNonHttpsToDynamicRegistrationRequest.ts";
import { CallDynamicRegistrationEndpoint } from "../condition/client/CallDynamicRegistrationEndpoint.ts";
import { CheckErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata } from "../condition/client/CheckErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata.ts";
import { CreateInitiateLoginUri } from "../condition/client/CreateInitiateLoginUri.ts";
import { EnsureContentTypeJson } from "../condition/client/EnsureContentTypeJson.ts";
import { EnsureHttpStatusCodeIs400 } from "../condition/client/EnsureHttpStatusCodeIs400.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ConditionResult, type ModuleVariantMetadata, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to OP-3rd_party-init-login-nohttps
// https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_3rd_party_init_login_nohttps
export class OIDCC3rdPartyInitLoginNonHttps extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-3rd_party-init-login-nohttps",
		displayName: "OIDCC: 3rd party initiated login - no https",
		summary:
			"Registers a client including the 'initiate_login_uri' parameter as a non-https url, which the server must reject.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		await this.callAndStopOnFailure(CreateInitiateLoginUri, "OIDCC-4", "OIDCR-2");
		await this.callAndStopOnFailure(AddInitiateLoginUriAsNonHttpsToDynamicRegistrationRequest, "OIDCC-4", "OIDCR-2");
	}

	protected override async configureDynamicClient(): Promise<void> {
		await this.createDynamicClientRegistrationRequest();

		await this.callAndStopOnFailure(CallDynamicRegistrationEndpoint, "RFC6749-3.1.2");

		this.env.mapKey("endpoint_response", "dynamic_registration_endpoint_response");
		await this.callAndContinueOnFailure(EnsureContentTypeJson, ConditionResult.FAILURE);
		await this.callAndContinueOnFailure(EnsureHttpStatusCodeIs400, ConditionResult.FAILURE);
		await this.callAndContinueOnFailure(
			CheckErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata,
			ConditionResult.FAILURE,
			"OIDCR-3.3",
		);
	}

	protected override async completeClientConfiguration(): Promise<void> {}

	protected override async performAuthorizationFlow(): Promise<void> {
		await this.fireTestFinished();
	}
}

import { BuildPlainRedirectToAuthorizationEndpoint } from "../condition/client/BuildPlainRedirectToAuthorizationEndpoint.ts";
import { CheckCallbackContentTypeIsFormUrlEncoded } from "../condition/client/CheckCallbackContentTypeIsFormUrlEncoded.ts";
import { CheckCallbackHttpMethodIsPost } from "../condition/client/CheckCallbackHttpMethodIsPost.ts";
import { CheckIfAuthorizationEndpointError } from "../condition/client/CheckIfAuthorizationEndpointError.ts";
import { CreateRedirectUri } from "../condition/client/CreateRedirectUri.ts";
import { ExtractClientNameFromStoredConfig } from "../condition/client/ExtractClientNameFromStoredConfig.ts";
import { ExtractInitialAccessTokenFromStoredConfig } from "../condition/client/ExtractInitialAccessTokenFromStoredConfig.ts";
import { GetDynamicServerConfiguration } from "../condition/client/GetDynamicServerConfiguration.ts";
import { RejectAuthCodeInUrlQuery } from "../condition/client/RejectAuthCodeInUrlQuery.ts";
import { RejectErrorInUrlQuery } from "../condition/client/RejectErrorInUrlQuery.ts";
import { SetScopeInClientConfigurationToOpenId } from "../condition/client/SetScopeInClientConfigurationToOpenId.ts";
import { StoreOriginalClientConfiguration } from "../condition/client/StoreOriginalClientConfiguration.ts";
import { UnregisterDynamicallyRegisteredClient } from "../condition/client/UnregisterDynamicallyRegisteredClient.ts";
import { CheckServerConfiguration } from "../condition/common/CheckServerConfiguration.ts";
import { CallDynamicRegistrationEndpointAndVerifySuccessfulResponse } from "../sequence/client/CallDynamicRegistrationEndpointAndVerifySuccessfulResponse.ts";
import { OIDCCCreateDynamicClientRegistrationRequest } from "../sequence/client/OIDCCCreateDynamicClientRegistrationRequest.ts";
import { SupportMTLSEndpointAliases } from "../sequence/client/SupportMTLSEndpointAliases.ts";
import { ClientAuthType } from "../variant/ClientAuthType.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ResponseMode } from "../variant/ResponseMode.ts";
import { ResponseType } from "../variant/ResponseType.ts";
import { ServerMetadata } from "../variant/ServerMetadata.ts";
import {
	AbstractRedirectServerTestModule,
	ConditionResult,
	Status,
	type ConditionSequenceClass,
	type ConditionSequenceSupplier,
	type JsonObject,
	type ModuleVariantMetadata,
} from "../framework/index.ts";
import {
	ConfigureClientForClientSecretJwt,
	ConfigureClientForMtls,
	CreateAuthorizationRequestSteps,
} from "./AbstractOIDCCServerTest.ts";

export abstract class AbstractOIDCCDynamicRegistrationTest extends AbstractRedirectServerTestModule {
	static override variants: ModuleVariantMetadata = {
		parameters: [ServerMetadata, ClientAuthType, ResponseType, ResponseMode, ClientRegistration],
		configurationFields: [
			{ parameter: ClientAuthType, value: "mtls", configurationFields: ["mtls.key", "mtls.cert", "mtls.ca"] },
			{
				parameter: ClientRegistration,
				value: "dynamic_client",
				configurationFields: ["client.client_name", "client.initial_access_token"],
			},
		],
		notApplicable: [
			{ parameter: ClientAuthType, values: ["client_attestation"] },
			{ parameter: ClientRegistration, values: ["static_client"] },
			{ parameter: ServerMetadata, values: ["static"] }, // dcr requires discovery
		],
		setup: [
			{ parameter: ClientAuthType, value: "client_secret_jwt", method: "setupClientSecretJwt" },
			{ parameter: ClientAuthType, value: "private_key_jwt", method: "setupPrivateKeyJwt" },
			{ parameter: ClientAuthType, value: "mtls", method: "setupMtls" },
		],
	};

	protected responseType!: ResponseType;
	protected formPost = false;

	protected profileCompleteClientConfiguration: ConditionSequenceSupplier | null = null;
	protected supportMTLSEndpointAliases: ConditionSequenceClass | null = null;

	// @VariantSetup(parameter = ClientAuthType.class, value = "client_secret_jwt")
	setupClientSecretJwt(): void {
		this.profileCompleteClientConfiguration = () => new ConfigureClientForClientSecretJwt();
	}

	// @VariantSetup(parameter = ClientAuthType.class, value = "private_key_jwt")
	setupPrivateKeyJwt(): void {
		this.profileCompleteClientConfiguration = null;
	}

	// @VariantSetup(parameter = ClientAuthType.class, value = "mtls")
	setupMtls(): void {
		this.profileCompleteClientConfiguration = () => new ConfigureClientForMtls(true, false, true);
		this.supportMTLSEndpointAliases = SupportMTLSEndpointAliases;
	}

	override async configure(
		config: JsonObject,
		baseUrl: string,
		externalUrlOverride: string,
		baseMtlsUrl: string,
	): Promise<void> {
		this.env.putString("base_url", baseUrl);
		this.env.putString("base_mtls_url", baseMtlsUrl);
		this.env.putString("external_url_override", externalUrlOverride);
		this.env.putObject("config", config);

		this.formPost = this.getVariant(ResponseMode) === ResponseMode.FORM_POST;

		const clientAuthType = this.getVariant(ClientAuthType);
		this.env.putString("client_auth_type", clientAuthType.toString());

		this.responseType = this.getVariant<ResponseType>(ResponseType);
		this.env.putString("response_type", this.responseType.toString());

		await this.callAndStopOnFailure(CreateRedirectUri);

		// this is inserted by the create call above, expose it to the test environment for publication
		this.exposeEnvString("redirect_uri");

		// Make sure we're calling the right server configuration
		await this.callAndStopOnFailure(GetDynamicServerConfiguration);

		if (this.supportMTLSEndpointAliases != null) {
			await this.call(this.sequence(this.supportMTLSEndpointAliases));
		}

		// make sure the server configuration passes some basic sanity checks
		await this.callAndStopOnFailure(CheckServerConfiguration);

		await this.callAndStopOnFailure(StoreOriginalClientConfiguration);
		await this.callAndStopOnFailure(ExtractClientNameFromStoredConfig);
		await this.callAndStopOnFailure(ExtractInitialAccessTokenFromStoredConfig);

		// Perform any custom configuration
		await this.onConfigure(config, baseUrl);

		await this.setStatus(Status.CONFIGURED);

		this.fireSetupDone();
	}

	protected async onConfigure(_config: JsonObject, _baseUrl: string): Promise<void> {
		// No custom configuration
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);

		await this.configureDynamicClient();
		if (this.profileCompleteClientConfiguration != null) {
			await this.call(this.sequence(this.profileCompleteClientConfiguration));
		}
		this.exposeEnvString("client_id");

		await this.performAuthorizationFlow();
	}

	protected async configureDynamicClient(): Promise<void> {
		await this.createDynamicClientRegistrationRequest();

		this.expose("client_name", this.env.getString("dynamic_registration_request", "client_name"));

		await this.call(this.sequence(CallDynamicRegistrationEndpointAndVerifySuccessfulResponse));

		await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenId);
	}

	protected async createDynamicClientRegistrationRequest(): Promise<void> {
		// Includes AddPublicJwksToDynamicRegistrationRequest, which corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Registration_jwks
		await this.call(new OIDCCCreateDynamicClientRegistrationRequest(this.responseType));
	}

	protected abstract performAuthorizationFlow(): Promise<void>;

	protected async createAuthorizationRequest(): Promise<void> {
		await this.call(new CreateAuthorizationRequestSteps(this.formPost));
	}

	protected async createAuthorizationRedirect(): Promise<void> {
		await this.callAndStopOnFailure(BuildPlainRedirectToAuthorizationEndpoint);
	}

	protected override async processCallback(): Promise<void> {
		// We're not expecting a callback, but we need to handle any potential error response

		if (this.formPost) {
			this.env.mapKey("authorization_endpoint_response", "callback_body_form_params");
			await this.callAndContinueOnFailure(CheckCallbackHttpMethodIsPost, ConditionResult.FAILURE, "OAuth2-FP-2");
			await this.callAndContinueOnFailure(
				CheckCallbackContentTypeIsFormUrlEncoded,
				ConditionResult.FAILURE,
				"OAuth2-FP-2",
			);
			await this.callAndContinueOnFailure(RejectAuthCodeInUrlQuery, ConditionResult.FAILURE, "OIDCC-3.3.2.5");
			await this.callAndContinueOnFailure(RejectErrorInUrlQuery, ConditionResult.FAILURE, "OAuth2-RT-5");
		} else if (this.responseType === ResponseType.CODE) {
			this.env.mapKey("authorization_endpoint_response", "callback_query_params");
		} else {
			this.env.mapKey("authorization_endpoint_response", "callback_params");

			await this.callAndContinueOnFailure(RejectAuthCodeInUrlQuery, ConditionResult.FAILURE, "OIDCC-3.3.2.5");
			await this.callAndContinueOnFailure(RejectErrorInUrlQuery, ConditionResult.FAILURE, "OAuth2-RT-5");
		}

		await this.callAndStopOnFailure(CheckIfAuthorizationEndpointError);

		this.eventLog.log(
			this.getName(),
			"Received a callback from the authorization endpoint. It is not necessary to complete login for this test.",
		);

		// We need to release the test lock, but we're still waiting for the placeholder to be filled.
		await this.setStatus(Status.WAITING);
	}

	override async cleanup(): Promise<void> {
		await this.unregisterClient();
	}

	async unregisterClient(): Promise<void> {
		if (this.getVariant(ClientRegistration) === ClientRegistration.DYNAMIC_CLIENT) {
			this.eventLog.startBlock("Unregister dynamically registered client");

			await this.call(
				this.condition(UnregisterDynamicallyRegisteredClient)
					.skipIfObjectsMissing("client")
					.onSkip(ConditionResult.INFO)
					.onFail(ConditionResult.WARNING)
					.dontStopOnFailure(),
			);

			this.eventLog.endBlock();
		}
	}
}

import {
	AbstractConditionSequence,
	AbstractRedirectServerTestModule,
	ConditionResult,
	isJsonArray,
	jsonArrayContains,
	Status,
	type ConditionSequence,
	type ConditionSequenceClass,
	type ConditionSequenceSupplier,
	type JsonObject,
	type ModuleVariantMetadata,
} from "../framework/index.ts";
import { AddBasicAuthClientSecretToRequest } from "../condition/client/AddBasicAuthClientSecretToRequest.ts";
import { AddClientIdToRequest } from "../condition/client/AddClientIdToRequest.ts";
import { AddFormBasedClientSecretToRequest } from "../condition/client/AddFormBasedClientSecretToRequest.ts";
import { AddNonceToAuthorizationEndpointRequest } from "../condition/client/AddNonceToAuthorizationEndpointRequest.ts";
import { AddStateToAuthorizationEndpointRequest } from "../condition/client/AddStateToAuthorizationEndpointRequest.ts";
import { BuildPlainRedirectToAuthorizationEndpoint } from "../condition/client/BuildPlainRedirectToAuthorizationEndpoint.ts";
import { CallProtectedResource } from "../condition/client/CallProtectedResource.ts";
import { CallTokenEndpointAndReturnFullResponse } from "../condition/client/CallTokenEndpointAndReturnFullResponse.ts";
import { CheckTokenEndpointHttpStatus200 } from "../condition/client/CheckTokenEndpointHttpStatus200.ts";
import { CheckCallbackContentTypeIsFormUrlEncoded } from "../condition/client/CheckCallbackContentTypeIsFormUrlEncoded.ts";
import { CheckCallbackHttpMethodIsPost } from "../condition/client/CheckCallbackHttpMethodIsPost.ts";
import { CheckErrorDescriptionFromAuthorizationEndpointResponseErrorContainsCRLFTAB } from "../condition/client/CheckErrorDescriptionFromAuthorizationEndpointResponseErrorContainsCRLFTAB.ts";
import { CheckForAccessTokenValue } from "../condition/client/CheckForAccessTokenValue.ts";
import { CheckForRefreshTokenValue } from "../condition/client/CheckForRefreshTokenValue.ts";
import { CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint } from "../condition/client/CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint.ts";
import { CheckIfAuthorizationEndpointError } from "../condition/client/CheckIfAuthorizationEndpointError.ts";
import { CheckIfTokenEndpointResponseError } from "../condition/client/CheckIfTokenEndpointResponseError.ts";
import { CheckMatchingCallbackParameters } from "../condition/client/CheckMatchingCallbackParameters.ts";
import { CheckServerKeysIsValid } from "../condition/client/CheckServerKeysIsValid.ts";
import { CheckStateInAuthorizationResponse } from "../condition/client/CheckStateInAuthorizationResponse.ts";
import { ConfigurationRequestsTestIsSkipped } from "../condition/client/ConfigurationRequestsTestIsSkipped.ts";
import { CreateAuthorizationEndpointRequestFromClientInformation } from "../condition/client/CreateAuthorizationEndpointRequestFromClientInformation.ts";
import { CreateRandomNonceValue } from "../condition/client/CreateRandomNonceValue.ts";
import { CreateRandomStateValue } from "../condition/client/CreateRandomStateValue.ts";
import { CreateRedirectUri } from "../condition/client/CreateRedirectUri.ts";
import { CreateTokenEndpointRequestForAuthorizationCodeGrant } from "../condition/client/CreateTokenEndpointRequestForAuthorizationCodeGrant.ts";
import { EnsureErrorFromAuthorizationEndpointResponse } from "../condition/client/EnsureErrorFromAuthorizationEndpointResponse.ts";
import { EnsureHttpStatusCodeIs200 } from "../condition/client/EnsureHttpStatusCodeIs200.ts";
import { EnsureServerConfigurationSupportsClientAuthNone } from "../condition/client/EnsureServerConfigurationSupportsClientAuthNone.ts";
import { EnsureServerConfigurationSupportsClientSecretBasic } from "../condition/client/EnsureServerConfigurationSupportsClientSecretBasic.ts";
import { EnsureServerConfigurationSupportsClientSecretPost } from "../condition/client/EnsureServerConfigurationSupportsClientSecretPost.ts";
import { EnsureServerConfigurationSupportsMTLS } from "../condition/client/EnsureServerConfigurationSupportsMTLS.ts";
import { EnsureServerConfigurationSupportsPrivateKeyJwt } from "../condition/client/EnsureServerConfigurationSupportsPrivateKeyJwt.ts";
import { ExtractAccessTokenFromAuthorizationResponse } from "../condition/client/ExtractAccessTokenFromAuthorizationResponse.ts";
import { ExtractAccessTokenFromTokenResponse } from "../condition/client/ExtractAccessTokenFromTokenResponse.ts";
import { ExtractAuthorizationCodeFromAuthorizationResponse } from "../condition/client/ExtractAuthorizationCodeFromAuthorizationResponse.ts";
import { ExtractClientNameFromStoredConfig } from "../condition/client/ExtractClientNameFromStoredConfig.ts";
import { ExtractExpiresInFromTokenEndpointResponse } from "../condition/client/ExtractExpiresInFromTokenEndpointResponse.ts";
import { ExtractIdTokenFromAuthorizationResponse } from "../condition/client/ExtractIdTokenFromAuthorizationResponse.ts";
import { ExtractIdTokenFromTokenResponse } from "../condition/client/ExtractIdTokenFromTokenResponse.ts";
import { ExtractInitialAccessTokenFromStoredConfig } from "../condition/client/ExtractInitialAccessTokenFromStoredConfig.ts";
import { ExtractJWKsFromStaticClientConfiguration } from "../condition/client/ExtractJWKsFromStaticClientConfiguration.ts";
import { ExtractMTLSCertificates2FromConfiguration } from "../condition/client/ExtractMTLSCertificates2FromConfiguration.ts";
import { ExtractMTLSCertificatesFromConfiguration } from "../condition/client/ExtractMTLSCertificatesFromConfiguration.ts";
import { ExtractTLSTestValuesFromServerConfiguration } from "../condition/client/ExtractTLSTestValuesFromServerConfiguration.ts";
import { FetchServerKeys } from "../condition/client/FetchServerKeys.ts";
import { GenerateJWKsFromClientSecret } from "../condition/client/GenerateJWKsFromClientSecret.ts";
import { GetDynamicServerConfiguration } from "../condition/client/GetDynamicServerConfiguration.ts";
import { GetStaticClientConfiguration } from "../condition/client/GetStaticClientConfiguration.ts";
import { GetStaticServerConfiguration } from "../condition/client/GetStaticServerConfiguration.ts";
import { RejectAuthCodeInAuthorizationEndpointResponse } from "../condition/client/RejectAuthCodeInAuthorizationEndpointResponse.ts";
import { RejectAuthCodeInUrlQuery } from "../condition/client/RejectAuthCodeInUrlQuery.ts";
import { RejectErrorInUrlQuery } from "../condition/client/RejectErrorInUrlQuery.ts";
import { SetAuthorizationEndpointRequestResponseModeToFormPost } from "../condition/client/SetAuthorizationEndpointRequestResponseModeToFormPost.ts";
import { SetAuthorizationEndpointRequestResponseTypeFromEnvironment } from "../condition/client/SetAuthorizationEndpointRequestResponseTypeFromEnvironment.ts";
import { SetProtectedResourceUrlToUserInfoEndpoint } from "../condition/client/SetProtectedResourceUrlToUserInfoEndpoint.ts";
import { SetScopeInClientConfigurationToOpenId } from "../condition/client/SetScopeInClientConfigurationToOpenId.ts";
import { StoreOriginalClientConfiguration } from "../condition/client/StoreOriginalClientConfiguration.ts";
import { UnregisterDynamicallyRegisteredClient } from "../condition/client/UnregisterDynamicallyRegisteredClient.ts";
import { ValidateClientJWKsPrivatePart } from "../condition/client/ValidateClientJWKsPrivatePart.ts";
import { ValidateErrorDescriptionFromAuthorizationEndpointResponseError } from "../condition/client/ValidateErrorDescriptionFromAuthorizationEndpointResponseError.ts";
import { ValidateErrorUriFromAuthorizationEndpointResponseError } from "../condition/client/ValidateErrorUriFromAuthorizationEndpointResponseError.ts";
import { ValidateExpiresIn } from "../condition/client/ValidateExpiresIn.ts";
import { ValidateIdTokenFromAuthorizationResponseEncryption } from "../condition/client/ValidateIdTokenFromAuthorizationResponseEncryption.ts";
import { ValidateIdTokenFromTokenResponseEncryption } from "../condition/client/ValidateIdTokenFromTokenResponseEncryption.ts";
import { ValidateIssIfPresentInAuthorizationResponse } from "../condition/client/ValidateIssIfPresentInAuthorizationResponse.ts";
import { ValidateMTLSCertificates2Header } from "../condition/client/ValidateMTLSCertificates2Header.ts";
import { ValidateMTLSCertificatesAsX509 } from "../condition/client/ValidateMTLSCertificatesAsX509.ts";
import { ValidateMTLSCertificatesHeader } from "../condition/client/ValidateMTLSCertificatesHeader.ts";
import { ValidateJwksSequence } from "../sequence/ValidateJwksSequence.ts";
import { VerifyIdTokenSubConsistentHybridFlow } from "../condition/client/VerifyIdTokenSubConsistentHybridFlow.ts";
import { CheckDistinctKeyIdValueInClientJWKs } from "../condition/common/CheckDistinctKeyIdValueInClientJWKs.ts";
import { CheckDistinctKeyIdValueInServerJWKs } from "../condition/common/CheckDistinctKeyIdValueInServerJWKs.ts";
import { CheckForKeyIdInServerJWKs } from "../condition/common/CheckForKeyIdInServerJWKs.ts";
import { CheckServerConfiguration } from "../condition/common/CheckServerConfiguration.ts";
import { AddMTLSClientAuthenticationToRequest } from "../sequence/client/AddMTLSClientAuthenticationToRequest.ts";
import { CallDynamicRegistrationEndpointAndVerifySuccessfulResponse } from "../sequence/client/CallDynamicRegistrationEndpointAndVerifySuccessfulResponse.ts";
import { CreateJWTClientAuthenticationAssertionAndAddToTokenEndpointRequest } from "../sequence/client/CreateJWTClientAuthenticationAssertionAndAddToTokenEndpointRequest.ts";
import { OIDCCCreateDynamicClientRegistrationRequest } from "../sequence/client/OIDCCCreateDynamicClientRegistrationRequest.ts";
import { PerformStandardIdTokenChecks } from "../sequence/client/PerformStandardIdTokenChecks.ts";
import { SupportMTLSEndpointAliases } from "../sequence/client/SupportMTLSEndpointAliases.ts";
import { ClientAuthType } from "../variant/ClientAuthType.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ResponseMode } from "../variant/ResponseMode.ts";
import { ResponseType } from "../variant/ResponseType.ts";
import { ServerMetadata } from "../variant/ServerMetadata.ts";

// @VariantParameters / @VariantConfigurationFields / @VariantHidesConfigurationFields / @VariantNotApplicable

export class ConfigureClientForClientSecretJwt extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(GenerateJWKsFromClientSecret);
	}
}

// Java: non-static inner class reading AbstractOIDCCServerTest.serverSupportsDiscovery
export class ConfigureClientForAuthTypeNone extends AbstractConditionSequence {
	private readonly serverSupportsDiscovery: boolean;

	constructor(serverSupportsDiscovery: boolean) {
		super();
		this.serverSupportsDiscovery = serverSupportsDiscovery;
	}

	override evaluate(): void {
		if (this.serverSupportsDiscovery) {
			this.callAndContinueOnFailure(EnsureServerConfigurationSupportsClientAuthNone, ConditionResult.FAILURE);
		}
	}
}

// Java: non-static inner class reading AbstractOIDCCServerTest.serverSupportsDiscovery
export class ConfigureClientForClientSecretBasic extends AbstractConditionSequence {
	private readonly serverSupportsDiscovery: boolean;

	constructor(serverSupportsDiscovery: boolean) {
		super();
		this.serverSupportsDiscovery = serverSupportsDiscovery;
	}

	override evaluate(): void {
		if (this.serverSupportsDiscovery) {
			this.callAndContinueOnFailure(EnsureServerConfigurationSupportsClientSecretBasic, ConditionResult.FAILURE);
		}
	}
}

// Java: non-static inner class reading AbstractOIDCCServerTest.serverSupportsDiscovery
export class ConfigureClientForClientSecretPost extends AbstractConditionSequence {
	private readonly serverSupportsDiscovery: boolean;

	constructor(serverSupportsDiscovery: boolean) {
		super();
		this.serverSupportsDiscovery = serverSupportsDiscovery;
	}

	override evaluate(): void {
		if (this.serverSupportsDiscovery) {
			this.callAndContinueOnFailure(EnsureServerConfigurationSupportsClientSecretPost, ConditionResult.FAILURE);
		}
	}
}

export class ConfigureClientForPrivateKeyJwt extends AbstractConditionSequence {
	private readonly serverSupportsDiscovery: boolean;

	constructor(serverSupportsDiscovery: boolean) {
		super();
		this.serverSupportsDiscovery = serverSupportsDiscovery;
	}

	override evaluate(): void {
		if (this.serverSupportsDiscovery) {
			this.callAndContinueOnFailure(EnsureServerConfigurationSupportsPrivateKeyJwt, ConditionResult.FAILURE);
		}
	}
}

export class ConfigureClientForMtls extends AbstractConditionSequence {
	private readonly serverSupportsDiscovery: boolean;
	private readonly secondClient: boolean;

	private readonly checkClientAuthMtlsSupported: boolean;

	constructor(serverSupportsDiscovery: boolean, secondClient: boolean, checkClientAuthMtlsSupported: boolean) {
		super();
		this.secondClient = secondClient;
		this.serverSupportsDiscovery = serverSupportsDiscovery;
		this.checkClientAuthMtlsSupported = checkClientAuthMtlsSupported;
	}

	override evaluate(): void {
		if (!this.secondClient) {
			if (this.serverSupportsDiscovery && this.checkClientAuthMtlsSupported) {
				this.callAndContinueOnFailure(EnsureServerConfigurationSupportsMTLS, ConditionResult.FAILURE);
			}
			this.callAndContinueOnFailure(ValidateMTLSCertificatesHeader, ConditionResult.WARNING);
			this.callAndContinueOnFailure(ExtractMTLSCertificatesFromConfiguration, ConditionResult.FAILURE);
		} else {
			// TODO: use environment mapping so we don't need two versions of these conditions
			this.callAndContinueOnFailure(ValidateMTLSCertificates2Header, ConditionResult.WARNING);
			this.callAndContinueOnFailure(ExtractMTLSCertificates2FromConfiguration, ConditionResult.FAILURE);
		}
		this.callAndContinueOnFailure(ValidateMTLSCertificatesAsX509, ConditionResult.FAILURE);
	}
}

export class ConfigureStaticClientForPrivateKeyJwt extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(ValidateClientJWKsPrivatePart, "RFC7517-1.1");
		this.callAndStopOnFailure(ExtractJWKsFromStaticClientConfiguration);
		this.callAndContinueOnFailure(CheckDistinctKeyIdValueInClientJWKs, ConditionResult.FAILURE, "RFC7517-4.5");
	}
}

export class ConfigureStaticClient extends AbstractConditionSequence {
	override evaluate(): void {
		// for auth types other than private_key_jwt we might still need a jwks if the server is returning
		// encrypted id_tokens; extract one if it's there.
		this.call(
			this.condition(ValidateClientJWKsPrivatePart)
				.skipIfElementMissing("client", "jwks")
				.onSkip(ConditionResult.INFO)
				.requirements("RFC7517-1.1")
				.onFail(ConditionResult.FAILURE),
		);

		this.call(
			this.condition(ExtractJWKsFromStaticClientConfiguration)
				.skipIfElementMissing("client", "jwks")
				.onSkip(ConditionResult.INFO)
				.onFail(ConditionResult.FAILURE),
		);

		this.call(
			this.condition(CheckDistinctKeyIdValueInClientJWKs)
				.skipIfElementMissing("client", "jwks")
				.onSkip(ConditionResult.INFO)
				.requirements("RFC7517-4.5")
				.onFail(ConditionResult.FAILURE),
		);
	}
}

export class AddAuthClientNoneAuthenticationToTokenRequest extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(AddClientIdToRequest);
	}
}

export class AddBasicAuthClientSecretAuthenticationToTokenRequest extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(AddBasicAuthClientSecretToRequest);
	}
}

export class AddFormBasedClientSecretAuthenticationToTokenRequest extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(AddFormBasedClientSecretToRequest);
	}
}

export class CreateAuthorizationRequestSteps extends AbstractConditionSequence {
	protected formPost: boolean;

	constructor(formPost: boolean) {
		super();
		this.formPost = formPost;
	}

	override evaluate(): void {
		this.callAndStopOnFailure(CreateAuthorizationEndpointRequestFromClientInformation);

		this.callAndStopOnFailure(CreateRandomStateValue);
		this.call(this.exec().exposeEnvironmentString("state"));
		this.callAndStopOnFailure(AddStateToAuthorizationEndpointRequest);

		this.callAndStopOnFailure(CreateRandomNonceValue);
		this.call(this.exec().exposeEnvironmentString("nonce"));
		this.callAndStopOnFailure(AddNonceToAuthorizationEndpointRequest);

		this.callAndStopOnFailure(SetAuthorizationEndpointRequestResponseTypeFromEnvironment);

		if (this.formPost) {
			this.callAndStopOnFailure(SetAuthorizationEndpointRequestResponseModeToFormPost);
		}
	}
}

export abstract class AbstractOIDCCServerTest extends AbstractRedirectServerTestModule {
	static override variants: ModuleVariantMetadata = {
		parameters: [ServerMetadata, ClientAuthType, ResponseType, ResponseMode, ClientRegistration],
		configurationFields: [
			{
				parameter: ServerMetadata,
				value: "static",
				configurationFields: [
					"server.issuer",
					"server.jwks_uri",
					"server.authorization_endpoint",
					"server.token_endpoint",
					"server.userinfo_endpoint",
				],
			},
			{ parameter: ServerMetadata, value: "discovery", configurationFields: ["server.discoveryUrl"] },
			{ parameter: ClientAuthType, value: "client_secret_basic", configurationFields: ["client.client_secret"] },
			{ parameter: ClientAuthType, value: "client_secret_post", configurationFields: ["client.client_secret"] },
			{
				parameter: ClientAuthType,
				value: "client_secret_jwt",
				configurationFields: ["client.client_secret", "client.client_secret_jwt_alg"],
			},
			{ parameter: ClientAuthType, value: "private_key_jwt", configurationFields: ["client.jwks"] },
			{ parameter: ClientAuthType, value: "mtls", configurationFields: ["mtls.key", "mtls.cert", "mtls.ca"] },
			{ parameter: ClientRegistration, value: "static_client", configurationFields: ["client.client_id"] },
			{
				parameter: ClientRegistration,
				value: "dynamic_client",
				configurationFields: ["client.client_name", "client.initial_access_token"],
			},
		],
		hidesConfigurationFields: [
			{
				parameter: ClientRegistration,
				value: "dynamic_client",
				configurationFields: ["client.client_secret", "client.jwks", "client2.client_secret", "client2.jwks"],
			},
			{
				parameter: ResponseType,
				value: "id_token",
				configurationFields: [
					"server.token_endpoint",
					/* we don't exclude "server.userinfo_endpoint" as this would prevent it appearing in the 'implicit' configuration
					 * form - see comment in TestPlanModuleWithVariant's constructor */
				],
			},
			{ parameter: ResponseType, value: "id_token token", configurationFields: ["server.token_endpoint"] },
		],
		notApplicable: [{ parameter: ClientAuthType, values: ["client_attestation"] }],
		setup: [
			{ parameter: ClientAuthType, value: "none", method: "setupNone" },
			{ parameter: ClientAuthType, value: "client_secret_basic", method: "setupClientSecretBasic" },
			{ parameter: ClientAuthType, value: "client_secret_post", method: "setupClientSecretPost" },
			{ parameter: ClientAuthType, value: "client_secret_jwt", method: "setupClientSecretJwt" },
			{ parameter: ClientAuthType, value: "private_key_jwt", method: "setupPrivateKeyJwt" },
			{ parameter: ClientAuthType, value: "mtls", method: "setupMtls" },
		],
	};

	protected responseType!: ResponseType;
	protected formPost = false;
	// Java: protected boolean serverSupportsDiscovery (renamed: TS cannot have a field and a method with the same
	// name; subclasses use the serverSupportsDiscovery() method)
	protected serverSupportsDiscoveryFlag = false;

	protected profileStaticClientConfiguration: ConditionSequenceClass | null = null;
	protected profileCompleteClientConfiguration: ConditionSequenceSupplier | null = null;
	protected addTokenEndpointClientAuthentication: ConditionSequenceClass | null = null;
	protected supportMTLSEndpointAliases: ConditionSequenceClass | null = null;

	// @VariantSetup(parameter = ClientAuthType.class, value = "none")
	setupNone(): void {
		this.profileStaticClientConfiguration = ConfigureStaticClient;
		this.profileCompleteClientConfiguration = () =>
			new ConfigureClientForAuthTypeNone(this.serverSupportsDiscoveryFlag);
		this.addTokenEndpointClientAuthentication = AddAuthClientNoneAuthenticationToTokenRequest;
	}

	// @VariantSetup(parameter = ClientAuthType.class, value = "client_secret_basic")
	setupClientSecretBasic(): void {
		this.profileStaticClientConfiguration = ConfigureStaticClient;
		this.profileCompleteClientConfiguration = () =>
			new ConfigureClientForClientSecretBasic(this.serverSupportsDiscoveryFlag);
		this.addTokenEndpointClientAuthentication = AddBasicAuthClientSecretAuthenticationToTokenRequest;
	}

	// @VariantSetup(parameter = ClientAuthType.class, value = "client_secret_post")
	setupClientSecretPost(): void {
		this.profileStaticClientConfiguration = ConfigureStaticClient;
		this.profileCompleteClientConfiguration = () =>
			new ConfigureClientForClientSecretPost(this.serverSupportsDiscoveryFlag);
		this.addTokenEndpointClientAuthentication = AddFormBasedClientSecretAuthenticationToTokenRequest;
	}

	// @VariantSetup(parameter = ClientAuthType.class, value = "client_secret_jwt")
	setupClientSecretJwt(): void {
		this.profileStaticClientConfiguration = ConfigureStaticClient;
		this.profileCompleteClientConfiguration = () => new ConfigureClientForClientSecretJwt();
		this.addTokenEndpointClientAuthentication = CreateJWTClientAuthenticationAssertionAndAddToTokenEndpointRequest;
	}

	// @VariantSetup(parameter = ClientAuthType.class, value = "private_key_jwt")
	setupPrivateKeyJwt(): void {
		this.profileStaticClientConfiguration = ConfigureStaticClientForPrivateKeyJwt;
		this.profileCompleteClientConfiguration = () =>
			new ConfigureClientForPrivateKeyJwt(this.serverSupportsDiscoveryFlag);
		this.addTokenEndpointClientAuthentication = CreateJWTClientAuthenticationAssertionAndAddToTokenEndpointRequest;
	}

	// @VariantSetup(parameter = ClientAuthType.class, value = "mtls")
	setupMtls(): void {
		this.profileStaticClientConfiguration = ConfigureStaticClient;
		this.profileCompleteClientConfiguration = () =>
			new ConfigureClientForMtls(this.serverSupportsDiscovery(), this.isSecondClient(), true);
		this.addTokenEndpointClientAuthentication = AddMTLSClientAuthenticationToRequest;
		this.supportMTLSEndpointAliases = SupportMTLSEndpointAliases;
	}

	// Java: final
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

		const skip = this.env.getBoolean("config", "skip_test");
		if (skip != null && skip) {
			// This is intended for use in our CI where we insist all tests run to completion
			// It would be used as a temporary measure in an 'override' where one of the environments we are testing
			// against is not able to run the test to completion due to an issue in that environments.
			await this.callAndContinueOnFailure(ConfigurationRequestsTestIsSkipped, ConditionResult.FAILURE);
			await this.fireTestFinished();
			return;
		}
		this.formPost = this.getVariant(ResponseMode) === ResponseMode.FORM_POST;
		this.serverSupportsDiscoveryFlag = this.getVariant(ServerMetadata) === ServerMetadata.DISCOVERY;

		const clientAuthType = this.getVariant(ClientAuthType);
		this.env.putString("client_auth_type", clientAuthType.toString());

		this.responseType = this.getVariant<ResponseType>(ResponseType);
		this.env.putString("response_type", this.responseType.toString());

		await this.callAndStopOnFailure(CreateRedirectUri);

		// this is inserted by the create call above, expose it to the test environment for publication
		this.exposeEnvString("redirect_uri");

		switch (this.getVariant(ServerMetadata)) {
			case ServerMetadata.DISCOVERY:
				await this.callAndStopOnFailure(GetDynamicServerConfiguration);
				break;
			case ServerMetadata.STATIC:
				await this.callAndStopOnFailure(GetStaticServerConfiguration);
				break;
		}

		if (this.supportMTLSEndpointAliases != null) {
			await this.call(this.sequence(this.supportMTLSEndpointAliases));
		}

		// make sure the server configuration passes some basic sanity checks
		await this.callAndStopOnFailure(CheckServerConfiguration);

		await this.callAndStopOnFailure(ExtractTLSTestValuesFromServerConfiguration);

		await this.callAndStopOnFailure(FetchServerKeys);
		await this.callAndContinueOnFailure(CheckServerKeysIsValid, ConditionResult.WARNING);
		await this.call(new ValidateJwksSequence("server_jwks", null, "server JWKS", "RFC7517-1.1"));
		await this.callAndContinueOnFailure(CheckForKeyIdInServerJWKs, ConditionResult.FAILURE, "OIDCC-10.1");
		await this.callAndContinueOnFailure(CheckDistinctKeyIdValueInServerJWKs, ConditionResult.FAILURE, "RFC7517-4.5");

		await this.skipTestIfSigningAlgorithmNotSupported();

		// Set up the client configuration
		await this.configureClient();

		await this.skipTestIfScopesNotSupported();

		// Set up the resource endpoint configuration
		await this.configureProtectedResourceUrl();

		// Perform any custom configuration
		await this.onConfigure(config, baseUrl);

		await this.setStatus(Status.CONFIGURED);

		this.fireSetupDone();
	}

	protected async skipTestIfSigningAlgorithmNotSupported(): Promise<void> {
		// Just apply for 'oidcc-idtoken-unsigned' test
	}

	protected async skipTestIfScopesNotSupported(): Promise<void> {
		// Just apply for scope tests
	}

	protected skipTestIfNoneUnsupported(): void {
		const el = this.env.getElementFromObject("server", "request_object_signing_alg_values_supported");
		if (el != null && isJsonArray(el)) {
			const serverValues = el;
			if (!jsonArrayContains(serverValues, "none")) {
				this.fireTestSkipped(
					"'none' is not listed in request_object_signing_alg_values_supported - assuming it is not supported.",
				);
			}
		}
	}

	protected async onConfigure(_config: JsonObject, _baseUrl: string): Promise<void> {
		// No custom configuration
	}

	protected async configureProtectedResourceUrl(): Promise<void> {
		// Set up the resource endpoint configuration
		await this.callAndStopOnFailure(SetProtectedResourceUrlToUserInfoEndpoint);
	}

	protected async configureClient(): Promise<void> {
		// Set up the client configuration
		switch (this.getVariant(ClientRegistration)) {
			case ClientRegistration.STATIC_CLIENT:
				await this.callAndStopOnFailure(GetStaticClientConfiguration);
				await this.configureStaticClient();
				break;
			case ClientRegistration.DYNAMIC_CLIENT:
				await this.callAndStopOnFailure(StoreOriginalClientConfiguration);
				await this.callAndStopOnFailure(ExtractClientNameFromStoredConfig);
				await this.callAndStopOnFailure(ExtractInitialAccessTokenFromStoredConfig);
				await this.configureDynamicClient();
				break;
		}

		this.exposeEnvString("client_id");

		await this.completeClientConfiguration();
	}

	protected async configureStaticClient(): Promise<void> {
		if (this.profileStaticClientConfiguration != null) {
			await this.call(this.sequence(this.profileStaticClientConfiguration));
		}
	}

	protected async createDynamicClientRegistrationRequest(): Promise<void> {
		// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Registration_Dynamic
		await this.call(new OIDCCCreateDynamicClientRegistrationRequest(this.responseType));

		this.expose("client_name", this.env.getString("dynamic_registration_request", "client_name"));
	}

	protected async configureDynamicClient(): Promise<void> {
		await this.createDynamicClientRegistrationRequest();

		await this.call(this.sequence(CallDynamicRegistrationEndpointAndVerifySuccessfulResponse));
	}

	protected async completeClientConfiguration(): Promise<void> {
		await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenId);

		if (this.profileCompleteClientConfiguration != null) {
			await this.call(this.sequence(this.profileCompleteClientConfiguration));
		}
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);
		await this.performAuthorizationFlow();
	}

	protected async performAuthorizationFlow(): Promise<void> {
		this.eventLog.startBlock(this.currentClientString() + "Make request to authorization endpoint");
		await this.createAuthorizationRequest();
		await this.createAuthorizationRedirect();
		await this.performRedirect();
		this.eventLog.endBlock();
	}

	protected async createAuthorizationRequest(): Promise<void> {
		await this.call(this.createAuthorizationRequestSequence());
	}

	protected createAuthorizationRequestSequence(): ConditionSequence {
		return new CreateAuthorizationRequestSteps(this.formPost);
	}

	protected async createAuthorizationRedirect(): Promise<void> {
		await this.callAndStopOnFailure(BuildPlainRedirectToAuthorizationEndpoint);
	}

	protected override async processCallback(): Promise<void> {
		this.eventLog.startBlock(this.currentClientString() + "Verify authorization endpoint response");

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
		} else if (this.isCodeFlow()) {
			this.env.mapKey("authorization_endpoint_response", "callback_query_params");
		} else {
			this.env.mapKey("authorization_endpoint_response", "callback_params");

			await this.callAndContinueOnFailure(RejectAuthCodeInUrlQuery, ConditionResult.FAILURE, "OIDCC-3.3.2.5");
			await this.callAndContinueOnFailure(RejectErrorInUrlQuery, ConditionResult.FAILURE, "OAuth2-RT-5");
		}

		await this.onAuthorizationCallbackResponse();
		this.eventLog.endBlock();
	}

	protected async onAuthorizationCallbackResponse(): Promise<void> {
		await this.callAndContinueOnFailure(CheckMatchingCallbackParameters, ConditionResult.FAILURE);
		await this.callAndContinueOnFailure(
			ValidateIssIfPresentInAuthorizationResponse,
			ConditionResult.FAILURE,
			"OAuth2-iss-2",
		);
		await this.callAndStopOnFailure(CheckIfAuthorizationEndpointError);
		await this.callAndContinueOnFailure(CheckStateInAuthorizationResponse, ConditionResult.FAILURE);
		if (this.responseType.includesCode()) {
			await this.callAndStopOnFailure(ExtractAuthorizationCodeFromAuthorizationResponse);
		}
		if (this.responseType.includesToken()) {
			await this.callAndStopOnFailure(ExtractAccessTokenFromAuthorizationResponse);
		}
		await this.handleSuccessfulAuthorizationEndpointResponse();
	}

	protected async handleSuccessfulAuthorizationEndpointResponse(): Promise<void> {
		if (this.responseType.includesIdToken()) {
			await this.skipIfMissing(
				["client_jwks"],
				null,
				ConditionResult.INFO,
				ValidateIdTokenFromAuthorizationResponseEncryption,
				ConditionResult.WARNING,
				"OIDCC-10.2",
			);
			await this.callAndStopOnFailure(ExtractIdTokenFromAuthorizationResponse);

			// save the id_token returned from the authorization endpoint
			this.env.putObject("authorization_endpoint_id_token", this.env.getObject("id_token") as JsonObject);

			await this.performAuthorizationEndpointIdTokenValidation();
		}
		if (this.responseType.includesCode()) {
			await this.performAuthorizationCodeValidation();
		}
		if (this.responseType.includesToken()) {
			await this.requestProtectedResource();
		}
		await this.performPostAuthorizationFlow();
	}

	protected async performAuthorizationEndpointIdTokenValidation(): Promise<void> {
		await this.performIdTokenValidation();
	}

	protected async performIdTokenValidation(): Promise<void> {
		await this.call(new PerformStandardIdTokenChecks());
	}

	protected async performAuthorizationCodeValidation(): Promise<void> {}

	protected async performPostAuthorizationFlow(): Promise<void> {
		if (this.responseType.includesCode()) {
			// call the token endpoint and complete the flow
			await this.createAuthorizationCodeRequest();
			await this.requestAuthorizationCode();
			await this.requestProtectedResource();
		}
		await this.onPostAuthorizationFlowComplete();
	}

	protected async createAuthorizationCodeRequest(): Promise<void> {
		await this.callAndStopOnFailure(CreateTokenEndpointRequestForAuthorizationCodeGrant);
		if (this.addTokenEndpointClientAuthentication != null) {
			this.mapClientAuthKeys("token_endpoint_request_form_parameters", "token_endpoint_request_headers");
			await this.call(this.sequence(this.addTokenEndpointClientAuthentication));
			this.unmapClientAuthKeys();
		}
	}

	protected async callTokenEndpoint(): Promise<void> {
		await this.callAndStopOnFailure(CallTokenEndpointAndReturnFullResponse);
		await this.callAndStopOnFailure(CheckTokenEndpointHttpStatus200);
	}

	protected async requestAuthorizationCode(): Promise<void> {
		await this.callTokenEndpoint();
		await this.callAndStopOnFailure(CheckIfTokenEndpointResponseError);
		await this.callAndStopOnFailure(CheckForAccessTokenValue);
		await this.callAndStopOnFailure(ExtractAccessTokenFromTokenResponse);

		await this.callAndContinueOnFailure(ExtractExpiresInFromTokenEndpointResponse, ConditionResult.INFO, "RFC6749-5.1"); // this is 'recommended' by the RFC, but we don't want to raise a warning on every test
		await this.skipIfMissing(
			["expires_in"],
			null,
			ConditionResult.INFO,
			ValidateExpiresIn,
			ConditionResult.FAILURE,
			"RFC6749-5.1",
		);

		await this.callAndContinueOnFailure(CheckForRefreshTokenValue, ConditionResult.INFO);

		await this.skipIfMissing(
			["client_jwks"],
			null,
			ConditionResult.INFO,
			ValidateIdTokenFromTokenResponseEncryption,
			ConditionResult.WARNING,
			"OIDCC-10.2",
		);
		await this.callAndStopOnFailure(ExtractIdTokenFromTokenResponse, "OIDCC-3.1.3.3", "OIDCC-3.3.3.3");

		// save the id_token returned from the token endpoint
		this.env.putObject("token_endpoint_id_token", this.env.getObject("id_token") as JsonObject);

		await this.additionalTokenEndpointResponseValidation();

		if (this.responseType.includesIdToken()) {
			await this.callAndContinueOnFailure(VerifyIdTokenSubConsistentHybridFlow, ConditionResult.FAILURE, "OIDCC-2");
		}
	}

	protected async additionalTokenEndpointResponseValidation(): Promise<void> {
		await this.performIdTokenValidation();
	}

	protected async requestProtectedResource(): Promise<void> {
		this.eventLog.startBlock(this.currentClientString() + "Userinfo endpoint tests");
		await this.callAndStopOnFailure(CallProtectedResource);
		await this.call(this.exec().mapKey("endpoint_response", "resource_endpoint_response_full"));
		await this.callAndContinueOnFailure(EnsureHttpStatusCodeIs200, ConditionResult.FAILURE);
		await this.call(this.exec().unmapKey("endpoint_response"));
		this.eventLog.endBlock();
	}

	/**
	 * Do generic checks on an error response from the authorization endpoint
	 *
	 * Generally called from onAuthorizationCallbackResponse. The caller stills needs to check for the exact specific
	 * error code their test scenario expects.
	 */
	protected async performGenericAuthorizationEndpointErrorResponseValidation(): Promise<void> {
		await this.callAndContinueOnFailure(CheckStateInAuthorizationResponse, ConditionResult.FAILURE);
		await this.callAndContinueOnFailure(
			ValidateIssIfPresentInAuthorizationResponse,
			ConditionResult.FAILURE,
			"OAuth2-iss-2",
		);
		await this.callAndContinueOnFailure(
			EnsureErrorFromAuthorizationEndpointResponse,
			ConditionResult.FAILURE,
			"OIDCC-3.1.2.6",
		);
		await this.callAndContinueOnFailure(
			RejectAuthCodeInAuthorizationEndpointResponse,
			ConditionResult.FAILURE,
			"OIDCC-3.1.2.6",
		);
		await this.callAndContinueOnFailure(
			CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint,
			ConditionResult.WARNING,
			"OIDCC-3.1.2.6",
		);
		await this.callAndContinueOnFailure(
			CheckErrorDescriptionFromAuthorizationEndpointResponseErrorContainsCRLFTAB,
			ConditionResult.WARNING,
			"RFC6749-4.1.2.1",
		);
		await this.callAndContinueOnFailure(
			ValidateErrorDescriptionFromAuthorizationEndpointResponseError,
			ConditionResult.FAILURE,
			"RFC6749-4.1.2.1",
		);
		await this.callAndContinueOnFailure(
			ValidateErrorUriFromAuthorizationEndpointResponseError,
			ConditionResult.FAILURE,
			"RFC6749-4.1.2.1",
		);
	}

	protected async onPostAuthorizationFlowComplete(): Promise<void> {
		await this.fireTestFinished();
	}

	override async cleanup(): Promise<void> {
		await this.unregisterClient();
	}

	async unregisterClient(): Promise<void> {
		if (this.getVariant(ClientRegistration) === ClientRegistration.DYNAMIC_CLIENT) {
			this.eventLog.startBlock(this.currentClientString() + "Unregister dynamically registered client");

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

	protected currentClientString(): string {
		return "";
	}

	protected isSecondClient(): boolean {
		return false;
	}

	protected serverSupportsDiscovery(): boolean {
		return this.serverSupportsDiscoveryFlag;
	}

	protected isCodeFlow(): boolean {
		return this.responseType === ResponseType.CODE;
	}

	protected isHybridFlow(): boolean {
		return this.responseType.includesCode() && !this.isCodeFlow();
	}

	protected isImplicitFlow(): boolean {
		return !this.responseType.includesCode();
	}
}

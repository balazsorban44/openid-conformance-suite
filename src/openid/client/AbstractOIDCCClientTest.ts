import {
	AbstractTestModule,
	ConditionResult,
	DATAUTILS_MEDIATYPE_APPLICATION_JWT_UTF8,
	OIDFJSON,
	RandomStringUtils,
	Status,
	TestFailureException,
	has,
	jsonResponse,
	modelAndView,
	redirectView,
	textResponse,
	type ConditionClass,
	type ConditionSequenceClass,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonObject,
	type ModuleVariantMetadata,
} from "../../framework/index.ts";
import { EnsureServerConfigurationHasRequiredOidcMetadata } from "../../condition/as/EnsureServerConfigurationHasRequiredOidcMetadata.ts";
import { AddAtHashToIdTokenClaims } from "../../condition/as/AddAtHashToIdTokenClaims.ts";
import { AddAuthTimeToIdTokenClaims } from "../../condition/as/AddAuthTimeToIdTokenClaims.ts";
import { AddCHashToIdTokenClaims } from "../../condition/as/AddCHashToIdTokenClaims.ts";
import { AddCodeToAuthorizationEndpointResponseParams } from "../../condition/as/AddCodeToAuthorizationEndpointResponseParams.ts";
import { AddIdTokenToAuthorizationEndpointResponseParams } from "../../condition/as/AddIdTokenToAuthorizationEndpointResponseParams.ts";
import { AddUnusableKeysToServerPublicJwks } from "../../condition/as/AddUnusableKeysToServerPublicJwks.ts";
import { AddIssAndAudToUserInfoResponse } from "../../condition/as/AddIssAndAudToUserInfoResponse.ts";
import { AddTokenToAuthorizationEndpointResponseParams } from "../../condition/as/AddTokenToAuthorizationEndpointResponseParams.ts";
import { CalculateAtHash } from "../../condition/as/CalculateAtHash.ts";
import { CalculateCHash } from "../../condition/as/CalculateCHash.ts";
import { ChangeTokenEndpointInServerConfigurationToMtls } from "../../condition/as/ChangeTokenEndpointInServerConfigurationToMtls.ts";
import { CheckClientIdMatchesOnTokenRequestIfPresent } from "../../condition/as/CheckClientIdMatchesOnTokenRequestIfPresent.ts";
import { CheckForUnexpectedClaimsInClaimsParameter } from "../../condition/as/CheckForUnexpectedClaimsInClaimsParameter.ts";
import { CheckForUnexpectedClaimsInRequestObject } from "../../condition/as/CheckForUnexpectedClaimsInRequestObject.ts";
import { CheckForUnexpectedOpenIdClaims } from "../../condition/as/CheckForUnexpectedOpenIdClaims.ts";
import { CheckPkceCodeVerifier } from "../../condition/as/CheckPkceCodeVerifier.ts";
import { CheckRequestClaimsParameterMemberValues } from "../../condition/as/CheckRequestClaimsParameterMemberValues.ts";
import { CheckRequestClaimsParameterValues } from "../../condition/as/CheckRequestClaimsParameterValues.ts";
import { CreateAuthorizationCode } from "../../condition/as/CreateAuthorizationCode.ts";
import { CreateAuthorizationEndpointResponseParams } from "../../condition/as/CreateAuthorizationEndpointResponseParams.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "../../condition/as/CreateEffectiveAuthorizationRequestParameters.ts";
import { CreateTokenEndpointResponse } from "../../condition/as/CreateTokenEndpointResponse.ts";
import { CreateWebfingerResponse } from "../../condition/as/CreateWebfingerResponse.ts";
import { DisallowMaxAgeEqualsZeroAndPromptNone } from "../../condition/as/DisallowMaxAgeEqualsZeroAndPromptNone.ts";
import { EncryptIdToken } from "../../condition/as/EncryptIdToken.ts";
import { EncryptUserInfoResponse } from "../../condition/as/EncryptUserInfoResponse.ts";
import { EnsureAuthorizationHttpRequestContainsOpenIDScope } from "../../condition/as/EnsureAuthorizationHttpRequestContainsOpenIDScope.ts";
import { EnsureAuthorizationRequestContainsPkceCodeChallenge } from "../../condition/as/EnsureAuthorizationRequestContainsPkceCodeChallenge.ts";
import { EnsureClientDoesNotHaveBothJwksAndJwksUri } from "../../condition/as/EnsureClientDoesNotHaveBothJwksAndJwksUri.ts";
import { EnsureClientHasJwksOrJwksUri } from "../../condition/as/EnsureClientHasJwksOrJwksUri.ts";
import { EnsureMatchingClientId } from "../../condition/as/EnsureMatchingClientId.ts";
import { EnsureNumericRequestObjectClaimsAreNotNull } from "../../condition/as/EnsureNumericRequestObjectClaimsAreNotNull.ts";
import { EnsureOpenIDInScopeRequest } from "../../condition/as/EnsureOpenIDInScopeRequest.ts";
import { EnsureOptionalAuthorizationRequestParametersMatchRequestObject } from "../../condition/as/EnsureOptionalAuthorizationRequestParametersMatchRequestObject.ts";
import { EnsureRequestDoesNotContainRequestObject } from "../../condition/as/EnsureRequestDoesNotContainRequestObject.ts";
import { EnsureRequestObjectDoesNotContainRequestOrRequestUri } from "../../condition/as/EnsureRequestObjectDoesNotContainRequestOrRequestUri.ts";
import { EnsureRequestObjectDoesNotContainSubWithClientId } from "../../condition/as/EnsureRequestObjectDoesNotContainSubWithClientId.ts";
import { EnsureRequestUriIsHttpsOrRequestObjectIsSigned } from "../../condition/as/EnsureRequestUriIsHttpsOrRequestObjectIsSigned.ts";
import { EnsureRequiredAuthorizationRequestParametersMatchRequestObject } from "../../condition/as/EnsureRequiredAuthorizationRequestParametersMatchRequestObject.ts";
import { EnsureResponseTypeIsCode } from "../../condition/as/EnsureResponseTypeIsCode.ts";
import { EnsureResponseTypeIsCodeIdToken } from "../../condition/as/EnsureResponseTypeIsCodeIdToken.ts";
import { EnsureResponseTypeIsCodeIdTokenToken } from "../../condition/as/EnsureResponseTypeIsCodeIdTokenToken.ts";
import { EnsureResponseTypeIsCodeToken } from "../../condition/as/EnsureResponseTypeIsCodeToken.ts";
import { EnsureResponseTypeIsIdToken } from "../../condition/as/EnsureResponseTypeIsIdToken.ts";
import { EnsureResponseTypeIsIdTokenToken } from "../../condition/as/EnsureResponseTypeIsIdTokenToken.ts";
import { EnsureValidRedirectUriForAuthorizationEndpointRequest } from "../../condition/as/EnsureValidRedirectUriForAuthorizationEndpointRequest.ts";
import { ExtractNonceFromAuthorizationRequest } from "../../condition/as/ExtractNonceFromAuthorizationRequest.ts";
import { ExtractRequestObject } from "../../condition/as/ExtractRequestObject.ts";
import { ExtractRequestedScopes } from "../../condition/as/ExtractRequestedScopes.ts";
import { FetchClientKeys } from "../../condition/as/FetchClientKeys.ts";
import { FetchRequestUriAndExtractRequestObject } from "../../condition/as/FetchRequestUriAndExtractRequestObject.ts";
import { FilterUserInfoForScopes } from "../../condition/as/FilterUserInfoForScopes.ts";
import { GenerateBearerAccessToken } from "../../condition/as/GenerateBearerAccessToken.ts";
import { GenerateIdTokenClaims } from "../../condition/as/GenerateIdTokenClaims.ts";
import { OIDCCAddRequestObjectSigningAlgValuesSupportedToServerConfiguration } from "../../condition/as/OIDCCAddRequestObjectSigningAlgValuesSupportedToServerConfiguration.ts";
import { OIDCCExtractServerSigningAlg } from "../../condition/as/OIDCCExtractServerSigningAlg.ts";
import { OIDCCGenerateServerConfiguration } from "../../condition/as/OIDCCGenerateServerConfiguration.ts";
import { OIDCCGenerateServerJWKs } from "../../condition/as/OIDCCGenerateServerJWKs.ts";
import { OIDCCGetStaticClientConfigurationForRPTests } from "../../condition/as/OIDCCGetStaticClientConfigurationForRPTests.ts";
import { OIDCCSignIdToken } from "../../condition/as/OIDCCSignIdToken.ts";
import { OIDCCValidateRequestObjectExp } from "../../condition/as/OIDCCValidateRequestObjectExp.ts";
import { SendAuthorizationResponseWithResponseModeFragment } from "../../condition/as/SendAuthorizationResponseWithResponseModeFragment.ts";
import { SendAuthorizationResponseWithResponseModeQuery } from "../../condition/as/SendAuthorizationResponseWithResponseModeQuery.ts";
import { SetRequestParameterSupportedToTrueInServerConfiguration } from "../../condition/as/SetRequestParameterSupportedToTrueInServerConfiguration.ts";
import { SetRequestUriParameterSupportedToTrueInServerConfiguration } from "../../condition/as/SetRequestUriParameterSupportedToTrueInServerConfiguration.ts";
import { SetTokenEndpointAuthMethodsSupportedToClientSecretBasicOnly } from "../../condition/as/SetTokenEndpointAuthMethodsSupportedToClientSecretBasicOnly.ts";
import { SetTokenEndpointAuthMethodsSupportedToClientSecretJWTOnly } from "../../condition/as/SetTokenEndpointAuthMethodsSupportedToClientSecretJWTOnly.ts";
import { SetTokenEndpointAuthMethodsSupportedToClientSecretPostOnly } from "../../condition/as/SetTokenEndpointAuthMethodsSupportedToClientSecretPostOnly.ts";
import { SetTokenEndpointAuthMethodsSupportedToPrivateKeyJWTOnly } from "../../condition/as/SetTokenEndpointAuthMethodsSupportedToPrivateKeyJWTOnly.ts";
import { SetTokenEndpointAuthMethodsSupportedToSelfSignedTlsClientAuthOnly } from "../../condition/as/SetTokenEndpointAuthMethodsSupportedToSelfSignedTlsClientAuthOnly.ts";
import { SetTokenEndpointAuthMethodsSupportedToTlsClientAuthOnly } from "../../condition/as/SetTokenEndpointAuthMethodsSupportedToTlsClientAuthOnly.ts";
import { SignUserInfoResponse } from "../../condition/as/SignUserInfoResponse.ts";
import { ValidateAuthorizationCode } from "../../condition/as/ValidateAuthorizationCode.ts";
import { ValidateEncryptedRequestObjectHasKid } from "../../condition/as/ValidateEncryptedRequestObjectHasKid.ts";
import { ValidateRedirectUriForTokenEndpointRequest } from "../../condition/as/ValidateRedirectUriForTokenEndpointRequest.ts";
import { ValidateRequestObjectAud } from "../../condition/as/ValidateRequestObjectAud.ts";
import { ValidateRequestObjectIat } from "../../condition/as/ValidateRequestObjectIat.ts";
import { ValidateRequestObjectIss } from "../../condition/as/ValidateRequestObjectIss.ts";
import { ValidateRequestObjectMaxAge } from "../../condition/as/ValidateRequestObjectMaxAge.ts";
import { ValidateRequestObjectSignature } from "../../condition/as/ValidateRequestObjectSignature.ts";
import { EnsureIdTokenEncryptedResponseAlgIsSetIfEncIsSet } from "../../condition/as/dynregistration/EnsureIdTokenEncryptedResponseAlgIsSetIfEncIsSet.ts";
import { EnsureRegistrationRequestContainsAtLeastOneContact } from "../../condition/as/dynregistration/EnsureRegistrationRequestContainsAtLeastOneContact.ts";
import { EnsureRequestObjectEncryptionAlgIsSetIfEncIsSet } from "../../condition/as/dynregistration/EnsureRequestObjectEncryptionAlgIsSetIfEncIsSet.ts";
import { EnsureUserinfoEncryptedResponseAlgIsSetIfEncIsSet } from "../../condition/as/dynregistration/EnsureUserinfoEncryptedResponseAlgIsSetIfEncIsSet.ts";
import { OIDCCExtractDynamicRegistrationRequest } from "../../condition/as/dynregistration/OIDCCExtractDynamicRegistrationRequest.ts";
import { OIDCCRegisterClient } from "../../condition/as/dynregistration/OIDCCRegisterClient.ts";
import { OIDCCValidateClientRedirectUris } from "../../condition/as/dynregistration/OIDCCValidateClientRedirectUris.ts";
import { SetClientIdTokenSignedResponseAlgToServerSigningAlg } from "../../condition/as/dynregistration/SetClientIdTokenSignedResponseAlgToServerSigningAlg.ts";
import { ValidateClientGrantTypes } from "../../condition/as/dynregistration/ValidateClientGrantTypes.ts";
import { ValidateClientLogoUris } from "../../condition/as/dynregistration/ValidateClientLogoUris.ts";
import { ValidateClientPolicyUris } from "../../condition/as/dynregistration/ValidateClientPolicyUris.ts";
import { ValidateClientRegistrationRequestSectorIdentifierUri } from "../../condition/as/dynregistration/ValidateClientRegistrationRequestSectorIdentifierUri.ts";
import { ValidateClientSubjectType } from "../../condition/as/dynregistration/ValidateClientSubjectType.ts";
import { ValidateClientTosUris } from "../../condition/as/dynregistration/ValidateClientTosUris.ts";
import { ValidateClientUris } from "../../condition/as/dynregistration/ValidateClientUris.ts";
import { ValidateDefaultAcrValues } from "../../condition/as/dynregistration/ValidateDefaultAcrValues.ts";
import { ValidateDefaultMaxAge } from "../../condition/as/dynregistration/ValidateDefaultMaxAge.ts";
import { ValidateIdTokenSignedResponseAlg } from "../../condition/as/dynregistration/ValidateIdTokenSignedResponseAlg.ts";
import { ValidateInitiateLoginUri } from "../../condition/as/dynregistration/ValidateInitiateLoginUri.ts";
import { ValidateRequestObjectSigningAlg } from "../../condition/as/dynregistration/ValidateRequestObjectSigningAlg.ts";
import { ValidateRequestUris } from "../../condition/as/dynregistration/ValidateRequestUris.ts";
import { ValidateRequireAuthTime } from "../../condition/as/dynregistration/ValidateRequireAuthTime.ts";
import { ValidateTokenEndpointAuthSigningAlg } from "../../condition/as/dynregistration/ValidateTokenEndpointAuthSigningAlg.ts";
import { ValidateUserinfoSignedResponseAlg } from "../../condition/as/dynregistration/ValidateUserinfoSignedResponseAlg.ts";
import { ConfigurationRequestsTestIsSkipped } from "../../condition/client/ConfigurationRequestsTestIsSkipped.ts";
import { ExtractClientNameFromStoredConfig } from "../../condition/client/ExtractClientNameFromStoredConfig.ts";
import { ExtractJWKsFromStaticClientConfiguration } from "../../condition/client/ExtractJWKsFromStaticClientConfiguration.ts";
import { StoreOriginalClientConfiguration } from "../../condition/client/StoreOriginalClientConfiguration.ts";
import { ValidateJwksSequence } from "../../sequence/ValidateJwksSequence.ts";
import { CheckDistinctKeyIdValueInClientJWKs } from "../../condition/common/CheckDistinctKeyIdValueInClientJWKs.ts";
import { CheckDistinctKeyIdValueInServerJWKs } from "../../condition/common/CheckDistinctKeyIdValueInServerJWKs.ts";
import { ClearAccessTokenFromRequest } from "../../condition/rs/ClearAccessTokenFromRequest.ts";
import { OIDCCExtractBearerAccessTokenFromRequest } from "../../condition/rs/OIDCCExtractBearerAccessTokenFromRequest.ts";
import { OIDCCLoadUserInfo } from "../../condition/rs/OIDCCLoadUserInfo.ts";
import { RequireBearerAccessToken } from "../../condition/rs/RequireBearerAccessToken.ts";
import { OIDCCRegisterClientWithClientSecretBasic } from "../../sequence/as/OIDCCRegisterClientWithClientSecretBasic.ts";
import { OIDCCRegisterClientWithClientSecretJwt } from "../../sequence/as/OIDCCRegisterClientWithClientSecretJwt.ts";
import { OIDCCRegisterClientWithClientSecretPost } from "../../sequence/as/OIDCCRegisterClientWithClientSecretPost.ts";
import { OIDCCRegisterClientWithNone } from "../../sequence/as/OIDCCRegisterClientWithNone.ts";
import { OIDCCRegisterClientWithPrivateKeyJwt } from "../../sequence/as/OIDCCRegisterClientWithPrivateKeyJwt.ts";
import { OIDCCRegisterClientWithSelfSignedTlsClientAuth } from "../../sequence/as/OIDCCRegisterClientWithSelfSignedTlsClientAuth.ts";
import { OIDCCRegisterClientWithTlsClientAuth } from "../../sequence/as/OIDCCRegisterClientWithTlsClientAuth.ts";
import { OIDCCValidateClientAuthenticationWithClientSecretBasic } from "../../sequence/as/OIDCCValidateClientAuthenticationWithClientSecretBasic.ts";
import { OIDCCValidateClientAuthenticationWithClientSecretJWT } from "../../sequence/as/OIDCCValidateClientAuthenticationWithClientSecretJWT.ts";
import { OIDCCValidateClientAuthenticationWithClientSecretPost } from "../../sequence/as/OIDCCValidateClientAuthenticationWithClientSecretPost.ts";
import { OIDCCValidateClientAuthenticationWithNone } from "../../sequence/as/OIDCCValidateClientAuthenticationWithNone.ts";
import { OIDCCValidateClientAuthenticationWithSelfSignedTlsClientAuth } from "../../sequence/as/OIDCCValidateClientAuthenticationWithSelfSignedTlsClientAuth.ts";
import { OIDCCValidateClientAuthenticationWithTlsClientAuth } from "../../sequence/as/OIDCCValidateClientAuthenticationWithTlsClientAuth.ts";
import { ValidateClientAuthenticationWithPrivateKeyJWT } from "../../sequence/as/ValidateClientAuthenticationWithPrivateKeyJWT.ts";
import { JWEUtil } from "../../util/JWEUtil.ts";
import { JWSUtil } from "../../util/JWSUtil.ts";
import { ClientRegistration } from "../../variant/ClientRegistration.ts";
import { ClientRequestType } from "../../variant/ClientRequestType.ts";
import { OIDCCClientAuthType } from "../../variant/OIDCCClientAuthType.ts";
import { ResponseMode } from "../../variant/ResponseMode.ts";
import { ResponseType } from "../../variant/ResponseType.ts";

// @VariantParameters / @VariantConfigurationFields / @VariantHidesConfigurationFields
export abstract class AbstractOIDCCClientTest extends AbstractTestModule {
	static override variants: ModuleVariantMetadata = {
		parameters: [OIDCCClientAuthType, ResponseType, ResponseMode, ClientRegistration, ClientRequestType],
		configurationFields: [
			{ parameter: OIDCCClientAuthType, value: "client_secret_basic", configurationFields: ["client.client_secret"] },
			{ parameter: OIDCCClientAuthType, value: "client_secret_post", configurationFields: ["client.client_secret"] },
			{
				parameter: OIDCCClientAuthType,
				value: "client_secret_jwt",
				configurationFields: ["client.client_secret", "client.client_secret_jwt_alg"],
			},
			{
				parameter: OIDCCClientAuthType,
				value: "private_key_jwt",
				configurationFields: ["client.jwks", "client.jwks_uri"],
			},
			{
				parameter: OIDCCClientAuthType,
				value: "tls_client_auth",
				configurationFields: [
					"client.tls_client_auth_subject_dn",
					"client.tls_client_auth_san_dns",
					"client.tls_client_auth_san_uri",
					"client.tls_client_auth_san_ip",
					"client.tls_client_auth_san_email",
				],
			},
			{
				parameter: OIDCCClientAuthType,
				value: "self_signed_tls_client_auth",
				configurationFields: ["client.jwks", "client.jwks_uri"],
			},
			{
				parameter: ClientRegistration,
				value: "static_client",
				configurationFields: ["client.client_id", "client.redirect_uri", "client.request_type"],
			},
		],
		hidesConfigurationFields: [
			{
				parameter: ClientRegistration,
				value: "dynamic_client",
				configurationFields: [
					"client.client_name",
					"client.client_secret",
					"client.jwks",
					"client.jwks_uri",
					"client.tls_client_auth_subject_dn",
					"client.tls_client_auth_san_dns",
					"client.tls_client_auth_san_uri",
					"client.tls_client_auth_san_ip",
					"client.tls_client_auth_san_email",
				],
			},
			{ parameter: OIDCCClientAuthType, value: "none", configurationFields: ["client.client_secret"] },
		],
		setup: [
			{ parameter: OIDCCClientAuthType, value: "none", method: "setupClientAuthNone" },
			{ parameter: OIDCCClientAuthType, value: "private_key_jwt", method: "setupPrivateKeyJwt" },
			{ parameter: OIDCCClientAuthType, value: "client_secret_basic", method: "setupClientSecretBasic" },
			{ parameter: OIDCCClientAuthType, value: "client_secret_jwt", method: "setupClientSecretJWT" },
			{ parameter: OIDCCClientAuthType, value: "client_secret_post", method: "setupClientSecretPost" },
			{ parameter: OIDCCClientAuthType, value: "tls_client_auth", method: "setupTlsClientAuth" },
			{
				parameter: OIDCCClientAuthType,
				value: "self_signed_tls_client_auth",
				method: "setupSelfSignedTlsClientAuth",
			},
		],
	};

	protected responseType!: ResponseType;
	protected responseMode!: ResponseMode;
	protected clientRequestType!: ClientRequestType;
	protected clientRegistrationType!: ClientRegistration;
	protected clientAuthType!: OIDCCClientAuthType;

	protected receivedDiscoveryRequest = false;
	protected receivedJwksRequest = false;
	protected receivedRegistrationRequest = false;
	protected receivedAuthorizationRequest = false;
	protected receivedTokenRequest = false;
	protected receivedUserinfoRequest = false;

	/**
	 * for how long the test will wait for negative tests
	 */
	protected waitTimeoutSeconds = 5;

	protected addTokenEndpointAuthMethodSupported: ConditionClass | null = null;
	protected validateClientAuthenticationSteps: ConditionSequenceClass | null = null;
	protected authorizationCodeGrantTypeProfileSteps: ConditionSequenceClass | null = null;
	protected authorizationEndpointProfileSteps: ConditionSequenceClass | null = null;
	protected clientRegistrationSteps: ConditionSequenceClass | null = null;

	protected getEffectiveResponseTypeVariant(): ResponseType {
		return this.getVariant<ResponseType>(ResponseType);
	}
	protected getEffectiveResponseModeVariant(): ResponseMode {
		return this.getVariant<ResponseMode>(ResponseMode);
	}
	protected getEffectiveClientRequestTypeVariant(): ClientRequestType {
		return this.getVariant<ClientRequestType>(ClientRequestType);
	}
	protected getEffectiveClientRegistrationVariant(): ClientRegistration {
		return this.getVariant<ClientRegistration>(ClientRegistration);
	}
	protected getEffectiveClientAuthTypeVariant(): OIDCCClientAuthType {
		return this.getVariant<OIDCCClientAuthType>(OIDCCClientAuthType);
	}

	override async configure(
		config: JsonObject,
		baseUrl: string,
		_externalUrlOverride: string,
		baseMtlsUrl: string,
	): Promise<void> {
		this.env.putString("base_url", baseUrl);
		this.env.putString("base_mtls_url", baseMtlsUrl);
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

		if (has(config, "waitTimeoutSeconds")) {
			this.waitTimeoutSeconds = OIDFJSON.getInt(config["waitTimeoutSeconds"]);
		}
		this.responseType = this.getEffectiveResponseTypeVariant();
		this.env.putString("response_type", this.responseType.toString());

		this.responseMode = this.getEffectiveResponseModeVariant();

		this.clientRequestType = this.getEffectiveClientRequestTypeVariant();

		this.clientRegistrationType = this.getEffectiveClientRegistrationVariant();

		this.clientAuthType = this.getEffectiveClientAuthTypeVariant();

		await this.configureServerConfiguration();

		if (this.addTokenEndpointAuthMethodSupported != null) {
			await this.callAndStopOnFailure(this.addTokenEndpointAuthMethodSupported);
		}
		await this.adjustTokenEndpointInServerConfigurationIfUsingMtls();

		this.exposeEnvString("discoveryUrl");
		this.exposeEnvString("issuer");

		await this.onServerConfigurationCompleted();

		await this.callAndStopOnFailure(EnsureServerConfigurationHasRequiredOidcMetadata, "OIDCD-3");

		await this.configureServerJWKS();

		await this.validateConfiguredServerJWKS();

		await this.configureUserInfo();

		await this.configureClientConfiguration();

		await this.onBeforeFireSetupDone();

		if (this.clientRegistrationType === ClientRegistration.STATIC_CLIENT) {
			await this.setServerSigningAlgorithm();
			await this.callAndStopOnFailure(SetClientIdTokenSignedResponseAlgToServerSigningAlg);
		}

		await this.setStatus(Status.CONFIGURED);
		this.fireSetupDone();
	}

	/**
	 * override if necessary
	 */
	protected async endTestIfRequiredAuthorizationRequestParametersAreMissing(): Promise<void> {}

	/**
	 * override if necessary
	 */
	protected async addCustomValuesToIdToken(): Promise<void> {}

	/**
	 * override if necessary
	 */
	protected async customizeIdTokenSignature(): Promise<void> {}

	/**
	 * called right before fireSetupDone is called
	 */
	protected async onBeforeFireSetupDone(): Promise<void> {}

	protected async validateTokenEndpointRequest(): Promise<void> {}

	protected async validateConfiguredServerJWKS(): Promise<void> {
		await this.call(
			new ValidateJwksSequence("server_jwks", null, "server signing keys", "RFC7517-1.1").allowingPrivateKeys(),
		);
		await this.callAndContinueOnFailure(CheckDistinctKeyIdValueInServerJWKs, ConditionResult.FAILURE, "RFC7517-4.5");
	}

	/**
	 * expected to add discoveryUrl and issuer to env
	 */
	protected async configureServerConfiguration(): Promise<void> {
		await this.callAndStopOnFailure(OIDCCGenerateServerConfiguration);
	}

	protected async onServerConfigurationCompleted(): Promise<void> {
		//fapi would call callAndStopOnFailure(CheckServerConfiguration.class); here
		switch (this.clientRequestType) {
			case ClientRequestType.REQUEST_OBJECT:
				await this.callAndStopOnFailure(SetRequestParameterSupportedToTrueInServerConfiguration, "OIDCC-6.1");
				await this.callAndStopOnFailure(
					OIDCCAddRequestObjectSigningAlgValuesSupportedToServerConfiguration,
					"OIDCC-6.1",
				);
				break;
			case ClientRequestType.REQUEST_URI:
				await this.callAndStopOnFailure(SetRequestUriParameterSupportedToTrueInServerConfiguration, "OIDCC-6.2");
				break;
			case ClientRequestType.PLAIN_HTTP_REQUEST:
				// nothing to do
				break;
		}
	}

	/**
	 * no-op unless client auth type is SELF_SIGNED_TLS_CLIENT_AUTH or TLS_CLIENT_AUTH
	 */
	protected async adjustTokenEndpointInServerConfigurationIfUsingMtls(): Promise<void> {
		if (
			this.clientAuthType === OIDCCClientAuthType.SELF_SIGNED_TLS_CLIENT_AUTH ||
			this.clientAuthType === OIDCCClientAuthType.TLS_CLIENT_AUTH
		) {
			await this.callAndStopOnFailure(ChangeTokenEndpointInServerConfigurationToMtls);
		}
	}

	/**
	 * override to modify the generated jwks
	 */
	protected async configureServerJWKS(): Promise<void> {
		await this.callAndStopOnFailure(OIDCCGenerateServerJWKs);
		// published in all RP tests rather than a dedicated module so the check does not depend on when
		// the client last fetched/cached the JWKS
		await this.callAndStopOnFailure(AddUnusableKeysToServerPublicJwks, "RFC7517-5");
	}

	protected async configureUserInfo(): Promise<void> {
		await this.callAndStopOnFailure(OIDCCLoadUserInfo);
	}

	protected async configureClientConfiguration(): Promise<void> {
		if (this.clientRegistrationType === ClientRegistration.STATIC_CLIENT) {
			await this.callAndStopOnFailure(OIDCCGetStaticClientConfigurationForRPTests);
			await this.processAndValidateClientJwks();
			await this.validateClientMetadata();
		} else if (this.clientRegistrationType === ClientRegistration.DYNAMIC_CLIENT) {
			// I am not sure the result of either of these condition calls is used
			await this.callAndContinueOnFailure(StoreOriginalClientConfiguration, ConditionResult.INFO);
			await this.callAndStopOnFailure(ExtractClientNameFromStoredConfig);
			//for dynamic clients, jwks_uri retrieval and jwks validation will be performed after registration
			//signing_algorithm will be also set after registration
		}
	}

	protected isClientJwksNeeded(): boolean {
		//or clientAuthType == ClientAuthType.self_signed_tls_client_auth
		if (
			this.clientAuthType === OIDCCClientAuthType.PRIVATE_KEY_JWT ||
			this.clientAuthType === OIDCCClientAuthType.SELF_SIGNED_TLS_CLIENT_AUTH
		) {
			return true;
		}

		const client = this.env.getObject("client") as JsonObject;

		if (
			this.clientRequestType === ClientRequestType.REQUEST_OBJECT ||
			this.clientRequestType === ClientRequestType.REQUEST_URI
		) {
			if (has(client, "request_object_signing_alg")) {
				const requestObjectSigningAlg = OIDFJSON.getString(client["request_object_signing_alg"]);
				if (
					requestObjectSigningAlg != null &&
					"none" !== requestObjectSigningAlg &&
					JWSUtil.isAsymmetricJWSAlgorithm(requestObjectSigningAlg)
				) {
					return true;
				}
			} else {
				/*
					request_object_signing_alg
					OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP.
					...The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used...
				 */
				//as per the above, jwks may or may not be needed, we can't know this until we process a request_object
				//this may lead to a failure later in the test due to missing client_public_jwks
			}
		}

		if (has(client, "id_token_encrypted_response_alg")) {
			const idTokenEncRespAlg = OIDFJSON.getString(client["id_token_encrypted_response_alg"]);
			if (idTokenEncRespAlg != null && JWEUtil.isAsymmetricJWEAlgorithm(idTokenEncRespAlg)) {
				return true;
			}
		}

		if (has(client, "userinfo_encrypted_response_alg")) {
			const userinfoEncRespAlg = OIDFJSON.getString(client["userinfo_encrypted_response_alg"]);
			if (userinfoEncRespAlg != null && JWEUtil.isAsymmetricJWEAlgorithm(userinfoEncRespAlg)) {
				return true;
			}
		}

		return false;
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);
		// nothing to do here
		await this.setStatus(Status.WAITING);
	}

	override async handleHttpMtls(
		path: string,
		_req: IncomingHttpRequest,
		_res: unknown,
		_session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		await this.setStatus(Status.RUNNING);

		const requestId = "incoming_request_" + RandomStringUtils.nextAlphanumeric(37);

		this.env.putObject(requestId, requestParts);

		await this.call(this.exec().mapKey("client_request", requestId));

		await this.validateTlsForIncomingHttpRequest();

		await this.call(this.exec().unmapKey("client_request"));

		let responseObject: Response;
		if (path === "token") {
			responseObject = await this.handleTokenEndpointRequest(requestId);
		} else {
			throw new TestFailureException(this.getId(), "Got unexpected MTLS HTTP call to " + path);
		}
		if (!(await this.finishTestIfAllRequestsAreReceived())) {
			await this.setStatus(Status.WAITING);
		}
		return responseObject;
	}

	/**
	 * Override to randomize jwks path
	 * @return
	 */
	protected getJwksPath(): string {
		return "jwks";
	}

	override async handleHttp(
		path: string,
		_req: IncomingHttpRequest,
		servletResponse: unknown,
		_session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		if (this.getStatus() === Status.FINISHED && path === "jwks") {
			//TODO temporary fix, until a finish-test endpoint is added
			//don't change state. we finish the test after userinfo but clients may send
			//a request to jwks endpoint when userinfo response is signed
		} else {
			await this.setStatus(Status.RUNNING);
		}

		const requestId = "incoming_request_" + RandomStringUtils.nextAlphanumeric(37);

		this.env.putObject(requestId, requestParts);

		await this.call(this.exec().mapKey("client_request", requestId));

		await this.validateTlsForIncomingHttpRequest();

		await this.call(this.exec().unmapKey("client_request"));

		const responseObject = await this.handleClientRequestForPath(requestId, path, servletResponse);

		if (this.getStatus() === Status.FINISHED && path === this.getJwksPath()) {
			//TODO temporary fix, until a finish-test endpoint is added
			//we want to allow jwks calls after the test is finished
		} else {
			if (!(await this.finishTestIfAllRequestsAreReceived())) {
				await this.setStatus(Status.WAITING);
			}
		}

		return responseObject;
	}

	protected async validateTlsForIncomingHttpRequest(): Promise<void> {}

	protected async handleClientRequestForPath(
		requestId: string,
		path: string,
		_servletResponse: unknown,
	): Promise<Response> {
		if (path === "authorize") {
			this.checkIfDiscoveryCalled(path);
			this.receivedAuthorizationRequest = true;
			return this.handleAuthorizationEndpointRequest(requestId);
		} else if (path === "token") {
			this.checkIfDiscoveryCalled(path);
			this.receivedTokenRequest = true;
			return this.handleTokenEndpointRequest(requestId);
		} else if (path === this.getJwksPath()) {
			this.checkIfDiscoveryCalled(path);
			this.receivedJwksRequest = true;
			return this.handleJwksEndpointRequest();
		} else if (path === "userinfo") {
			this.checkIfDiscoveryCalled(path);
			this.checkIfJWKCalled(path);
			this.receivedUserinfoRequest = true;
			return this.handleUserinfoEndpointRequest(requestId);
		} else if (path === "register" && this.clientRegistrationType === ClientRegistration.DYNAMIC_CLIENT) {
			this.checkIfDiscoveryCalled(path);
			this.receivedRegistrationRequest = true;
			return this.handleRegistrationEndpointRequest(requestId);
		} else if (path === ".well-known/openid-configuration") {
			this.receivedDiscoveryRequest = true;
			return this.handleDiscoveryEndpointRequest();
		} else {
			throw new TestFailureException(this.getId(), "Got unexpected HTTP call to " + path);
		}
	}

	protected async handleDiscoveryEndpointRequest(): Promise<Response> {
		await this.call(this.exec().startBlock("Discovery endpoint"));
		const serverConfiguration = this.env.getObject("server");
		await this.call(this.exec().endBlock());
		return jsonResponse(serverConfiguration, 200);
	}

	protected async handleUserinfoEndpointRequest(requestId: string): Promise<Response> {
		await this.call(this.exec().startBlock("Userinfo endpoint").mapKey("incoming_request", requestId));

		await this.validateUserinfoRequest();

		const user = await this.prepareUserinfoResponse();

		await this.callAndStopOnFailure(ClearAccessTokenFromRequest);

		await this.signUserInfoResponseIfNecessary();

		await this.encryptUserInfoResponseIfNecessary();

		await this.call(this.exec().unmapKey("incoming_request").endBlock());

		const encryptedUserinfoResponse = this.env.getString("encrypted_user_info_endpoint_response");
		//If the UserInfo Response is signed and/or encrypted, then the Claims are returned in a
		//JWT and the content-type MUST be application/jwt.
		if (encryptedUserinfoResponse != null) {
			return this.createApplicationJwtResponse(encryptedUserinfoResponse);
		} else {
			const signedUserinfoResponse = this.env.getString("signed_user_info_endpoint_response");
			if (signedUserinfoResponse != null) {
				return this.createApplicationJwtResponse(signedUserinfoResponse);
			}
		}
		//neither signed nor encrypted
		return jsonResponse(user, 200);
	}

	protected async signUserInfoResponseIfNecessary(): Promise<void> {
		//If signed, the UserInfo Response SHOULD contain the Claims iss (issuer) and aud (audience) as members.
		await this.skipIfElementMissing(
			"client",
			"userinfo_signed_response_alg",
			ConditionResult.INFO,
			AddIssAndAudToUserInfoResponse,
			ConditionResult.FAILURE,
			"OIDCC-5.3.2",
		);

		await this.skipIfElementMissing(
			"client",
			"userinfo_signed_response_alg",
			ConditionResult.INFO,
			SignUserInfoResponse,
			ConditionResult.FAILURE,
			"OIDCC-5.3.2",
		);
	}

	protected async encryptUserInfoResponseIfNecessary(): Promise<void> {
		await this.skipIfElementMissing(
			"client",
			"userinfo_encrypted_response_alg",
			ConditionResult.INFO,
			EncryptUserInfoResponse,
			ConditionResult.FAILURE,
			"OIDCC-5.3.2",
		);
	}

	protected createApplicationJwtResponse(body: string): Response {
		return textResponse(body, 200, { "content-type": DATAUTILS_MEDIATYPE_APPLICATION_JWT_UTF8 });
	}

	/**
	 * returns true if fireTestFinished is called
	 *
	 * @return
	 */
	protected async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		let fireTestFinishedCalled = false;
		switch (this.responseType) {
			case ResponseType.CODE:
				if (this.receivedUserinfoRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
			case ResponseType.CODE_ID_TOKEN:
				if (this.receivedUserinfoRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
			case ResponseType.ID_TOKEN:
				//TODO test may never end if the client caches the jwks
				if (this.receivedAuthorizationRequest && this.receivedJwksRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
			case ResponseType.CODE_TOKEN:
				if (this.receivedUserinfoRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
			case ResponseType.CODE_ID_TOKEN_TOKEN:
				if (this.receivedUserinfoRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
			case ResponseType.ID_TOKEN_TOKEN:
				if (this.receivedUserinfoRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
		}
		return fireTestFinishedCalled;
	}

	protected async prepareUserinfoResponse(): Promise<JsonObject | null> {
		await this.callAndStopOnFailure(FilterUserInfoForScopes, "OIDCC-5.4");
		const user = this.env.getObject("user_info_endpoint_response");
		return user;
	}

	protected async validateUserinfoRequest(): Promise<void> {
		await this.extractBearerTokenFromUserinfoRequest();
		await this.callAndStopOnFailure(RequireBearerAccessToken, "OIDCC-5.3.1");
	}

	protected checkIfDiscoveryCalled(_path: string): void {}

	protected checkIfJWKCalled(_path: string): void {}
	/**
	 * Support any of
	 * - Authorization Request Header Field
	 * - Form-Encoded Body Parameter
	 * - URI Query Parameter
	 */
	protected async extractBearerTokenFromUserinfoRequest(): Promise<void> {
		await this.callAndStopOnFailure(OIDCCExtractBearerAccessTokenFromRequest, "RFC6750-2", "OIDCC-5.3.1");
	}

	protected async handleJwksEndpointRequest(): Promise<Response> {
		await this.call(this.exec().startBlock("Jwks endpoint"));
		const jwks = this.env.getObject("server_public_jwks");
		await this.call(this.exec().endBlock());
		return jsonResponse(jwks, 200);
	}

	protected async handleTokenEndpointRequest(requestId: string): Promise<Response> {
		await this.call(this.exec().mapKey("token_endpoint_request", requestId));

		const grantType = this.env.getString("token_endpoint_request", "body_form_params.grant_type");
		if (grantType == null) {
			throw new TestFailureException(
				this.getId(),
				"Token endpoint body does not contain the mandatory 'grant_type' parameter",
			);
		}

		if ("refresh_token" === grantType) {
			await this.call(this.exec().startBlock("Token endpoint - Refresh Request"));
		} else {
			await this.call(this.exec().startBlock("Token endpoint"));
		}

		await this.validateTokenEndpointRequest();

		await this.callAndContinueOnFailure(
			CheckClientIdMatchesOnTokenRequestIfPresent,
			ConditionResult.FAILURE,
			"RFC6749-3.2.1",
		);

		if (this.validateClientAuthenticationSteps != null) {
			await this.call(this.sequence(this.validateClientAuthenticationSteps));
		}

		if ("authorization_code" === grantType) {
			// we're doing the authorization code grant for user access
			return this.authorizationCodeGrantType(requestId);
		} else if ("refresh_token" === grantType) {
			return this.refreshTokenGrantType(requestId);
		} else {
			throw new TestFailureException(
				this.getId(),
				"Got a grant type on the token endpoint we didn't understand: " + grantType,
			);
		}
	}

	protected async refreshTokenGrantType(_requestId: string): Promise<Response> {
		throw new TestFailureException(this.getId(), "refresh_token grant type is not implemented for this test");
	}

	/**
	 * http request is mapped to "dynamic_registration_request" before this call
	 */
	protected async validateRegistrationRequest(): Promise<void> {
		//because the python suite requires this
		await this.callAndContinueOnFailure(EnsureRegistrationRequestContainsAtLeastOneContact, ConditionResult.INFO);

		//the following conditions are used for both static client validation and dynamic registration validation
		//so they require "client" env entry
		this.env.mapKey("client", "dynamic_registration_request");
		await this.validateClientMetadata();
		this.env.unmapKey("client");
		await this.callAndContinueOnFailure(
			ValidateClientRegistrationRequestSectorIdentifierUri,
			ConditionResult.FAILURE,
			"OIDCR-2",
			"OIDCR-5",
		);
	}

	/**
	 * jwks and jwks_uri will be validated in validateClientJwks
	 */
	protected async validateClientMetadata(): Promise<void> {
		await this.callAndContinueOnFailure(ValidateClientGrantTypes, ConditionResult.FAILURE, "OIDCR-2");
		await this.callAndContinueOnFailure(OIDCCValidateClientRedirectUris, ConditionResult.FAILURE, "OIDCR-2");

		await this.callAndContinueOnFailure(ValidateClientLogoUris, ConditionResult.FAILURE, "OIDCR-2");
		await this.callAndContinueOnFailure(ValidateClientUris, ConditionResult.FAILURE, "OIDCR-2");
		await this.callAndContinueOnFailure(ValidateClientPolicyUris, ConditionResult.FAILURE, "OIDCR-2");
		await this.callAndContinueOnFailure(ValidateClientTosUris, ConditionResult.FAILURE, "OIDCR-2");

		await this.callAndContinueOnFailure(ValidateClientSubjectType, ConditionResult.FAILURE, "OIDCR-2");
		await this.skipIfElementMissing(
			"client",
			"id_token_signed_response_alg",
			ConditionResult.INFO,
			ValidateIdTokenSignedResponseAlg,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);

		await this.callAndContinueOnFailure(
			EnsureIdTokenEncryptedResponseAlgIsSetIfEncIsSet,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);

		//userinfo
		await this.skipIfElementMissing(
			"client",
			"userinfo_signed_response_alg",
			ConditionResult.INFO,
			ValidateUserinfoSignedResponseAlg,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);
		await this.callAndContinueOnFailure(
			EnsureUserinfoEncryptedResponseAlgIsSetIfEncIsSet,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);

		//request object
		await this.skipIfElementMissing(
			"client",
			"request_object_signing_alg",
			ConditionResult.INFO,
			ValidateRequestObjectSigningAlg,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);
		await this.callAndContinueOnFailure(
			EnsureRequestObjectEncryptionAlgIsSetIfEncIsSet,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);

		//not validating token_endpoint_auth_method as we will override it anyway

		await this.skipIfElementMissing(
			"client",
			"token_endpoint_auth_signing_alg",
			ConditionResult.INFO,
			ValidateTokenEndpointAuthSigningAlg,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);

		await this.callAndContinueOnFailure(ValidateDefaultMaxAge, ConditionResult.WARNING, "OIDCR-2");

		await this.skipIfElementMissing(
			"client",
			"require_auth_time",
			ConditionResult.INFO,
			ValidateRequireAuthTime,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);

		await this.skipIfElementMissing(
			"client",
			"default_acr_values",
			ConditionResult.INFO,
			ValidateDefaultAcrValues,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);

		await this.skipIfElementMissing(
			"client",
			"initiate_login_uri",
			ConditionResult.INFO,
			ValidateInitiateLoginUri,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);

		await this.skipIfElementMissing(
			"client",
			"request_uris",
			ConditionResult.INFO,
			ValidateRequestUris,
			ConditionResult.FAILURE,
			"OIDCR-2",
		);
	}

	protected async handleRegistrationEndpointRequest(requestId: string): Promise<Response> {
		await this.call(this.exec().startBlock("Registration endpoint").mapKey("incoming_request", requestId));

		await this.callAndStopOnFailure(OIDCCExtractDynamicRegistrationRequest);

		await this.validateRegistrationRequest();

		const registeredClient = await this.registerClient();

		await this.call(this.exec().unmapKey("incoming_request").endBlock());

		return jsonResponse(registeredClient, 201);
	}

	/**
	 * Override to add additional steps to be executed after the variant (client authentication)
	 * steps are executed
	 * @return
	 */
	protected getAdditionalClientRegistrationSteps(): ConditionSequenceClass | null {
		return null;
	}

	/**
	 * clients are not persisted anywhere
	 * they are only valid for the duration of the test
	 * @return
	 */
	protected async registerClient(): Promise<JsonObject | null> {
		await this.callAndStopOnFailure(OIDCCRegisterClient);

		if (this.clientRegistrationSteps != null) {
			await this.call(this.sequence(this.clientRegistrationSteps));
		}
		const additionalSteps = this.getAdditionalClientRegistrationSteps();
		if (additionalSteps != null) {
			await this.call(this.sequence(additionalSteps));
		}
		await this.processAndValidateClientJwks();

		//set signing_algorithm after registration
		await this.setServerSigningAlgorithm();
		//set id_token_signed_response_alg to the actual server signing algorithm
		await this.callAndStopOnFailure(SetClientIdTokenSignedResponseAlgToServerSigningAlg);

		const client = this.env.getObject("client");
		return client;
	}

	/**
	 * - runs basic checks
	 * - fetches jwks_uri if provided
	 * - calls validateClientJwks()
	 */
	protected async processAndValidateClientJwks(): Promise<void> {
		const clientJwksNeeded = this.isClientJwksNeeded();
		if (clientJwksNeeded) {
			//initial validation
			await this.callAndStopOnFailure(EnsureClientHasJwksOrJwksUri);
		}
		await this.callAndStopOnFailure(EnsureClientDoesNotHaveBothJwksAndJwksUri, "OIDCR-2");

		//fetch client jwks from jwks_uri, if a jwks_uri is found
		await this.fetchClientJwksFromJwksUri();

		//at this point jwks has been downloaded from jwks_uri and added to client.jwks
		const client = this.env.getObject("client") as JsonObject;
		if (has(client, "jwks")) {
			await this.callAndStopOnFailure(ExtractJWKsFromStaticClientConfiguration);
			await this.validateClientJwks();
		}
	}

	protected async validateClientJwks(): Promise<void> {
		await this.call(new ValidateJwksSequence("client", "jwks", "client configuration", "RFC7517-1.1"));
		await this.callAndContinueOnFailure(CheckDistinctKeyIdValueInClientJWKs, ConditionResult.FAILURE, "RFC7517-4.5");
	}

	/**
	 * from this point on the client will contain both jwks and jwks_uri
	 */
	protected async fetchClientJwksFromJwksUri(): Promise<void> {
		await this.skipIfElementMissing(
			"client",
			"jwks_uri",
			ConditionResult.INFO,
			FetchClientKeys,
			ConditionResult.FAILURE,
			"OIDCC-10.1.1",
			"OIDCC-10.2.1",
		);
	}

	protected async validateAuthorizationCodeGrantType(): Promise<void> {
		await this.callAndStopOnFailure(ValidateAuthorizationCode, "OIDCC-3.1.3.2");

		await this.callAndContinueOnFailure(
			ValidateRedirectUriForTokenEndpointRequest,
			ConditionResult.FAILURE,
			"OIDCC-3.1.3.2",
		);
	}

	protected async createIdToken(isAuthorizationCodeGrantType: boolean): Promise<void> {
		await this.generateIdTokenClaims();

		if (isAuthorizationCodeGrantType) {
			//token endpoint called with code
			if (this.authorizationCodeGrantTypeProfileSteps != null) {
				await this.call(this.sequence(this.authorizationCodeGrantTypeProfileSteps));
			}
			await this.addAtHashToIdToken();
		} else {
			//authorization endpoint
			if (this.authorizationEndpointProfileSteps != null) {
				await this.call(this.sequence(this.authorizationEndpointProfileSteps));
			}
			await this.addCHashToIdToken();
			await this.addAtHashToIdToken();
			//s_hash is not applicable to core tests. Commenting out just in case it's needed in the future
			//addSHashToIdToken();
		}

		if (isAuthorizationCodeGrantType || this.responseType.includesIdToken()) {
			await this.addAuthTimeToIdToken();
		}

		await this.addCustomValuesToIdToken();

		await this.signIdToken();

		await this.customizeIdTokenSignature();

		await this.encryptIdTokenIfNecessary();
	}

	protected async encryptIdTokenIfNecessary(): Promise<void> {
		await this.skipIfElementMissing(
			"client",
			"id_token_encrypted_response_alg",
			ConditionResult.INFO,
			EncryptIdToken,
			ConditionResult.FAILURE,
			"OIDCC-10.2",
		);
	}

	/*
	//s_hash is not applicable to core tests. Commenting out just in case it's needed in the future
	protected void addSHashToIdToken() {
		skipIfElementMissing(CreateEffectiveAuthorizationRequestParameters.ENV_KEY, CreateEffectiveAuthorizationRequestParameters.STATE, Condition.ConditionResult.INFO,
			CalculateSHash.class, Condition.ConditionResult.FAILURE);
		skipIfMissing(null, new String[] { "s_hash" }, Condition.ConditionResult.INFO,
			AddSHashToIdTokenClaims.class, Condition.ConditionResult.FAILURE);
	}
	*/
	protected async addAtHashToIdToken(): Promise<void> {
		await this.skipIfMissing(
			null,
			["at_hash"],
			ConditionResult.INFO,
			AddAtHashToIdTokenClaims,
			ConditionResult.FAILURE,
			"OIDCC-3.3.2.11",
		);
	}

	protected async addCHashToIdToken(): Promise<void> {
		await this.skipIfMissing(
			null,
			["c_hash"],
			ConditionResult.INFO,
			AddCHashToIdTokenClaims,
			ConditionResult.FAILURE,
			"OIDCC-3.3.2.11",
		);
	}

	protected async addAuthTimeToIdToken(): Promise<void> {
		await this.skipIfElementMissing(
			"effective_authorization_endpoint_request",
			"max_age",
			ConditionResult.INFO,
			AddAuthTimeToIdTokenClaims,
			ConditionResult.FAILURE,
			"OIDCC-3.1.2.1",
		);
	}

	protected async authorizationCodeGrantType(_requestId: string): Promise<Response> {
		await this.validateAuthorizationCodeGrantType();

		if (this.env.containsObject("code_challenge")) {
			await this.call(this.sequence(CheckPkceCodeVerifier));
		}

		await this.generateAccessToken();

		await this.createIdToken(true);

		await this.createRefreshToken(false);

		await this.callAndStopOnFailure(CreateTokenEndpointResponse, "OIDCC-3.1.3.3");

		await this.call(this.exec().unmapKey("token_endpoint_request").endBlock());

		return jsonResponse(this.env.getObject("token_endpoint_response"), 200);
	}

	/**
	 * does nothing by default. to be overridden in refresh token tests
	 * @param isRefreshTokenGrant
	 */
	protected async createRefreshToken(_isRefreshTokenGrant: boolean): Promise<void> {}

	protected async generateIdTokenClaims(): Promise<void> {
		await this.callAndStopOnFailure(GenerateIdTokenClaims);
	}

	protected async signIdToken(): Promise<void> {
		await this.callAndStopOnFailure(OIDCCSignIdToken, "OIDCC-2");
	}

	protected async fetchAndProcessRequestUri(): Promise<void> {
		await this.callAndStopOnFailure(FetchRequestUriAndExtractRequestObject, "OIDCC-6.2");
		await this.callAndStopOnFailure(EnsureRequestUriIsHttpsOrRequestObjectIsSigned, "OIDCC-6.2");
	}

	protected async extractAuthorizationEndpointRequestParameters(): Promise<void> {
		if (this.clientRequestType === ClientRequestType.REQUEST_URI) {
			await this.fetchAndProcessRequestUri();
		} else if (this.clientRequestType === ClientRequestType.REQUEST_OBJECT) {
			await this.callAndStopOnFailure(ExtractRequestObject, "OIDCC-6.1");
		} else {
			//handle plain http request case
			await this.callAndStopOnFailure(EnsureRequestDoesNotContainRequestObject, "OIDCC-6.1");
		}

		await this.callAndStopOnFailure(EnsureAuthorizationHttpRequestContainsOpenIDScope, "OIDCC-6.1", "OIDCC-6.2");

		if (
			this.clientRequestType === ClientRequestType.REQUEST_OBJECT ||
			this.clientRequestType === ClientRequestType.REQUEST_URI
		) {
			await this.validateRequestObject();
			await this.callAndStopOnFailure(
				EnsureRequiredAuthorizationRequestParametersMatchRequestObject,
				"OIDCC-6.1",
				"OIDCC-6.2",
			);
			await this.skipIfElementMissing(
				"authorization_request_object",
				"jwe_header",
				ConditionResult.INFO,
				ValidateEncryptedRequestObjectHasKid,
				ConditionResult.FAILURE,
				"OIDCC-10.2",
				"OIDCC-10.2.1",
			);
			await this.callAndContinueOnFailure(
				EnsureOptionalAuthorizationRequestParametersMatchRequestObject,
				ConditionResult.WARNING,
				"OIDCC-6.1",
				"OIDCC-6.2",
			);
		}

		await this.callAndStopOnFailure(CreateEffectiveAuthorizationRequestParameters, "OIDCC-6.1", "OIDCC-6.2");

		await this.callAndStopOnFailure(ExtractRequestedScopes);

		await this.extractNonceFromAuthorizationEndpointRequestParameters();

		await this.skipIfElementMissing(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.CODE_CHALLENGE,
			ConditionResult.INFO,
			EnsureAuthorizationRequestContainsPkceCodeChallenge,
			ConditionResult.FAILURE,
			"RFC7636-4.3",
		);
	}

	protected async extractNonceFromAuthorizationEndpointRequestParameters(): Promise<void> {
		const responseType = this.env.getString(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.RESPONSE_TYPE,
		);
		if (responseType != null && responseType.includes("id_token")) {
			await this.callAndStopOnFailure(
				ExtractNonceFromAuthorizationRequest,
				ConditionResult.FAILURE,
				"OIDCC-3.1.2.1",
				"OIDCC-3.2.2.1",
			);
		} else {
			await this.callAndContinueOnFailure(ExtractNonceFromAuthorizationRequest, ConditionResult.INFO, "OIDCC-3.1.2.1");
		}
	}

	/**
	 * end the test here if required parameters are missing
	 */
	protected async validateAuthorizationEndpointRequestParameters(): Promise<void> {
		await this.validateResponseTypeAuthorizationRequestParameter();

		await this.callAndStopOnFailure(EnsureMatchingClientId, "OIDCC-3.1.2.1");

		await this.callAndStopOnFailure(EnsureValidRedirectUriForAuthorizationEndpointRequest, "OIDCC-3.1.2.1");

		await this.endTestIfRequiredAuthorizationRequestParametersAreMissing();

		await this.callAndStopOnFailure(EnsureOpenIDInScopeRequest, "OIDCC-3.1.2.1");

		await this.disallowMaxAge0AndPromptNone();
	}

	/**
	 * To be overridden in OIDCCClientTestFormPostError
	 * or any similar classes that want to trigger an error
	 * by allowing max_age=0 and prompt=none
	 */
	protected async disallowMaxAge0AndPromptNone(): Promise<void> {
		await this.callAndStopOnFailure(DisallowMaxAgeEqualsZeroAndPromptNone, "OIDCC-3.1.2.3");
	}

	protected async validateRequestObject(): Promise<void> {
		await this.skipIfElementMissing(
			"authorization_request_object",
			"claims.exp",
			ConditionResult.INFO,
			OIDCCValidateRequestObjectExp,
			ConditionResult.FAILURE,
			"RFC7519-4.1.4",
		);
		await this.callAndContinueOnFailure(ValidateRequestObjectIat, ConditionResult.WARNING, "OIDCC-6.1");
		await this.callAndContinueOnFailure(EnsureNumericRequestObjectClaimsAreNotNull, ConditionResult.WARNING, "OIDCC-13.3");
		await this.callAndContinueOnFailure(ValidateRequestObjectMaxAge, ConditionResult.FAILURE, "OIDCC-13.3");
		await this.callAndContinueOnFailure(
			EnsureRequestObjectDoesNotContainRequestOrRequestUri,
			ConditionResult.WARNING,
			"OIDCC-6.1",
		);
		await this.callAndContinueOnFailure(
			EnsureRequestObjectDoesNotContainSubWithClientId,
			ConditionResult.WARNING,
			"JAR-10.8",
		);

		const alg = this.env.getString("authorization_request_object", "header.alg");

		if (this.allowUnsignedRequestObjects() && "none" === alg) {
			//Nimbusds will throw an exception if a request object with alg:none contains a signature
		} else {
			//https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
			// The Request Object MAY be signed or unsigned (plaintext).
			// When it is plaintext, this is indicated by use of the none algorithm [JWA] in the JOSE Header.
			// If signed, the Request Object SHOULD contain the Claims iss (issuer) and aud (audience) as members.
			// The iss value SHOULD be the Client ID of the RP, unless it was signed by a different party than the RP.
			// The aud value SHOULD be or include the OP's Issuer Identifier URL.
			await this.callAndContinueOnFailure(ValidateRequestObjectIss, ConditionResult.WARNING, "OIDCC-6.1");
			await this.callAndContinueOnFailure(ValidateRequestObjectAud, ConditionResult.WARNING, "OIDCC-6.1");

			//This may happen when the client does not contain both request_object_signing_alg and jwks/jwks_uri
			//and a signed request object is received. We can't validate the signature.
			//Using skipIfMissing to avoid an ugly missing required environment entry error thrown by the framework
			await this.skipIfMissing(
				["client_public_jwks"],
				null,
				ConditionResult.FAILURE,
				ValidateRequestObjectSignature,
				ConditionResult.FAILURE,
				"OIDCC-6.1",
			);
		}
	}

	/**
	 * Override to disallow unsigned request objects.
	 * By default they are allowed
	 * @return
	 */
	protected allowUnsignedRequestObjects(): boolean {
		return true;
	}

	protected async validateResponseTypeAuthorizationRequestParameter(): Promise<void> {
		switch (this.responseType) {
			case ResponseType.CODE:
				await this.callAndStopOnFailure(EnsureResponseTypeIsCode);
				break;
			case ResponseType.ID_TOKEN:
				await this.callAndStopOnFailure(EnsureResponseTypeIsIdToken);
				break;
			case ResponseType.CODE_ID_TOKEN:
				await this.callAndStopOnFailure(EnsureResponseTypeIsCodeIdToken);
				break;
			case ResponseType.CODE_ID_TOKEN_TOKEN:
				await this.callAndStopOnFailure(EnsureResponseTypeIsCodeIdTokenToken);
				break;
			case ResponseType.CODE_TOKEN:
				await this.callAndStopOnFailure(EnsureResponseTypeIsCodeToken);
				break;
			case ResponseType.ID_TOKEN_TOKEN:
				await this.callAndStopOnFailure(EnsureResponseTypeIsIdTokenToken);
				break;
			default:
				throw new TestFailureException(this.getId(), "Unexpected response_type" + this.responseType.toString());
		}
	}

	protected async setServerSigningAlgorithm(): Promise<void> {
		await this.callAndStopOnFailure(OIDCCExtractServerSigningAlg);
	}

	protected async createAuthorizationCode(): Promise<void> {
		await this.callAndStopOnFailure(CreateAuthorizationCode);

		//c_hash, s_hash won't work when id_token_signed_response_alg is none

		if ("none" !== this.env.getString("signing_algorithm")) {
			await this.callAndStopOnFailure(CalculateCHash, "OIDCC-3.3.2.11");
		}
	}

	protected async generateAccessToken(): Promise<void> {
		await this.callAndStopOnFailure(GenerateBearerAccessToken);
		if ("none" !== this.env.getString("signing_algorithm")) {
			await this.callAndStopOnFailure(CalculateAtHash, "OIDCC-3.3.2.11");
		}
	}

	protected setAuthorizationEndpointRequestParamsForHttpMethod(): void {
		const httpMethod = this.env.getString("authorization_endpoint_http_request", "method");
		const httpRequestObj = this.env.getObject("authorization_endpoint_http_request") as JsonObject;
		if ("POST" === httpMethod) {
			this.env.putObject(
				"authorization_endpoint_http_request_params",
				httpRequestObj["body_form_params"] as JsonObject,
			);
		} else if ("GET" === httpMethod) {
			this.env.putObject(
				"authorization_endpoint_http_request_params",
				httpRequestObj["query_string_params"] as JsonObject,
			);
		} else {
			//this should not happen?
			throw new TestFailureException(this.getId(), "Got unexpected HTTP method to authorization endpoint");
		}
	}

	protected getAuthorizationEndpointBlockText(): string {
		return "Authorization endpoint";
	}

	// @UserFacing
	protected async handleAuthorizationEndpointRequest(requestId: string): Promise<Response> {
		await this.call(
			this.exec()
				.startBlock(this.getAuthorizationEndpointBlockText())
				.mapKey("authorization_endpoint_http_request", requestId),
		);
		this.setAuthorizationEndpointRequestParamsForHttpMethod();

		await this.extractAuthorizationEndpointRequestParameters();

		await this.validateAuthorizationEndpointRequestParameters();

		await this.skipIfElementMissing(
			"authorization_request_object",
			"claims",
			ConditionResult.INFO,
			CheckForUnexpectedClaimsInRequestObject,
			ConditionResult.WARNING,
			"RFC6749-4.1.1",
			"OIDCC-3.1.2.1",
			"RFC7636-4.3",
			"OAuth2-RT-2.1",
			"RFC7519-4.1",
			"DPOP-10",
			"RFC8485-4.1",
			"RFC8707-2.1",
			"RFC9396-2",
		);

		await this.skipIfElementMissing(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			"claims",
			ConditionResult.INFO,
			CheckForUnexpectedClaimsInClaimsParameter,
			ConditionResult.WARNING,
			"OIDCC-5.5",
		);
		await this.skipIfElementMissing(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			"claims",
			ConditionResult.INFO,
			CheckForUnexpectedOpenIdClaims,
			ConditionResult.WARNING,
			"OIDCC-5.1",
			"OIDCC-5.5.1.1",
			"BrazilOB-5.2.2.3",
			"BrazilOB-5.2.2.4",
			"OBSP-3.4",
		);
		await this.skipIfElementMissing(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			"claims",
			ConditionResult.INFO,
			CheckRequestClaimsParameterValues,
			ConditionResult.FAILURE,
			"OIDCC-5.5",
		);
		await this.skipIfElementMissing(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			"claims",
			ConditionResult.INFO,
			CheckRequestClaimsParameterMemberValues,
			ConditionResult.FAILURE,
			"OIDCC-5.5.1",
		);

		if (this.responseType.includesCode()) {
			await this.createAuthorizationCode();
		}

		if (this.responseType.includesToken()) {
			await this.generateAccessToken();
		}

		if (this.responseType.includesIdToken()) {
			await this.createIdToken(false);
		}

		await this.callAndStopOnFailure(CreateAuthorizationEndpointResponseParams);

		if (this.responseType.includesCode()) {
			await this.callAndStopOnFailure(AddCodeToAuthorizationEndpointResponseParams, "OIDCC-3.3.2.5");
		}
		if (this.responseType.includesIdToken()) {
			await this.callAndStopOnFailure(AddIdTokenToAuthorizationEndpointResponseParams, "OIDCC-3.3.2.5");
		}
		if (this.responseType.includesToken()) {
			await this.callAndStopOnFailure(AddTokenToAuthorizationEndpointResponseParams, "OIDCC-3.3.2.5");
		}

		await this.customizeAuthorizationEndpointResponseParams();

		let viewToReturn: Response;
		if (this.responseMode.isFormPost()) {
			viewToReturn = await this.generateFormPostResponse();
		} else {
			await this.redirectFromAuthorizationEndpoint();

			this.exposeEnvString("authorization_endpoint_response_redirect");

			const redirectTo = this.env.getString("authorization_endpoint_response_redirect") as string;

			viewToReturn = redirectView(redirectTo);
		}

		this.env.putString("auth_time", String(Math.floor(Date.now() / 1000)));

		await this.call(this.exec().unmapKey("authorization_endpoint_http_request").endBlock());
		return viewToReturn;
	}

	/**
	 * Called right before the response is generated
	 * Override to customize response parameters
	 */
	protected async customizeAuthorizationEndpointResponseParams(): Promise<void> {}

	protected async generateFormPostResponse(): Promise<Response> {
		const responseParams = this.env.getObject("authorization_endpoint_response_params") as JsonObject;
		const redirectUri = responseParams["redirect_uri"];
		delete responseParams["redirect_uri"];
		const formActionUrl = OIDFJSON.getString(redirectUri);

		return modelAndView("formPostResponseMode", {
			formAction: formActionUrl,
			formParameters: responseParams,
		});
	}

	protected async redirectFromAuthorizationEndpoint(): Promise<void> {
		if (this.responseType.includesIdToken() || this.responseType.includesToken()) {
			await this.callAndStopOnFailure(SendAuthorizationResponseWithResponseModeFragment, "OIDCC-3.3.2.5");
		} else if (this.responseType.includesCode()) {
			await this.callAndStopOnFailure(SendAuthorizationResponseWithResponseModeQuery, "OIDCC-3.3.2.5");
		} else {
			throw new TestFailureException(this.getId(), "Unexpected response_type" + this.responseType.toString());
		}
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "none")
	setupClientAuthNone(): void {
		this.addTokenEndpointAuthMethodSupported = null;
		this.validateClientAuthenticationSteps = OIDCCValidateClientAuthenticationWithNone;
		this.clientRegistrationSteps = OIDCCRegisterClientWithNone;
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "private_key_jwt")
	setupPrivateKeyJwt(): void {
		this.addTokenEndpointAuthMethodSupported = SetTokenEndpointAuthMethodsSupportedToPrivateKeyJWTOnly;
		this.validateClientAuthenticationSteps = ValidateClientAuthenticationWithPrivateKeyJWT;
		this.clientRegistrationSteps = OIDCCRegisterClientWithPrivateKeyJwt;
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "client_secret_basic")
	setupClientSecretBasic(): void {
		this.addTokenEndpointAuthMethodSupported = SetTokenEndpointAuthMethodsSupportedToClientSecretBasicOnly;
		this.validateClientAuthenticationSteps = OIDCCValidateClientAuthenticationWithClientSecretBasic;
		this.clientRegistrationSteps = OIDCCRegisterClientWithClientSecretBasic;
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "client_secret_jwt")
	setupClientSecretJWT(): void {
		this.addTokenEndpointAuthMethodSupported = SetTokenEndpointAuthMethodsSupportedToClientSecretJWTOnly;
		this.validateClientAuthenticationSteps = OIDCCValidateClientAuthenticationWithClientSecretJWT;
		this.clientRegistrationSteps = OIDCCRegisterClientWithClientSecretJwt;
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "client_secret_post")
	setupClientSecretPost(): void {
		this.addTokenEndpointAuthMethodSupported = SetTokenEndpointAuthMethodsSupportedToClientSecretPostOnly;
		this.validateClientAuthenticationSteps = OIDCCValidateClientAuthenticationWithClientSecretPost;
		this.clientRegistrationSteps = OIDCCRegisterClientWithClientSecretPost;
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "tls_client_auth")
	setupTlsClientAuth(): void {
		this.addTokenEndpointAuthMethodSupported = SetTokenEndpointAuthMethodsSupportedToTlsClientAuthOnly;
		this.validateClientAuthenticationSteps = OIDCCValidateClientAuthenticationWithTlsClientAuth;
		this.clientRegistrationSteps = OIDCCRegisterClientWithTlsClientAuth;
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "self_signed_tls_client_auth")
	setupSelfSignedTlsClientAuth(): void {
		this.addTokenEndpointAuthMethodSupported = SetTokenEndpointAuthMethodsSupportedToSelfSignedTlsClientAuthOnly;
		this.validateClientAuthenticationSteps = OIDCCValidateClientAuthenticationWithSelfSignedTlsClientAuth;
		this.clientRegistrationSteps = OIDCCRegisterClientWithSelfSignedTlsClientAuth;
	}

	/**
	 * Only use in tests that need to wait for a timeout
	 * As the client hasn't called an endpoint after waitTimeoutSeconds (from configuration) seconds,
	 * assume it has correctly detected the error and aborted.
	 */
	protected startWaitingForTimeout(): void {
		this.getTestExecutionManager().scheduleInBackground(async () => {
			if (this.getStatus() === Status.WAITING) {
				await this.setStatus(Status.RUNNING);
				await this.fireTestFinished();
			}
			return "done";
		}, this.waitTimeoutSeconds * 1000);
	}

	/**
	 * override to validate the webfinger resource
	 * @param resourcePrefix
	 */
	protected validateWebfingerRequestResource(_resourcePrefix: string): void {}
	/**
	 *
	 * @param resourcePrefix can be acct or https
	 * @return
	 */
	async handleWebfingerRequest(
		requestedTestName: string,
		resourcePrefix: string,
		resource: string,
		requestParts: JsonObject,
	): Promise<JsonObject | null> {
		await this.setStatus(Status.RUNNING);
		await this.call(this.exec().startBlock("Webfinger Request"));
		//this should not happen but just in case
		if (this.getName() !== requestedTestName) {
			throw new TestFailureException(
				this.getId(),
				"Test name in webfinger request does not match current test name. " +
					"Requested=" +
					requestedTestName +
					" actual=" +
					this.getName(),
			);
		}
		this.validateWebfingerRequestResource(resourcePrefix);
		this.env.putObject("incoming_webfinger_request", requestParts);
		this.env.putString("incoming_webfinger_resource", resource);
		await this.callAndStopOnFailure(CreateWebfingerResponse, "OIDCD-2");
		await this.call(this.exec().endBlock());
		await this.setStatus(Status.WAITING);
		return this.env.getObject("webfinger_response");
	}
}

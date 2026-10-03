import { CheckDiscEndpointAllEndpointsAreHttps } from "../condition/client/CheckDiscEndpointAllEndpointsAreHttps.ts";
import { CheckDiscEndpointClaimsParameterSupported } from "../condition/client/CheckDiscEndpointClaimsParameterSupported.ts";
import { CheckDiscEndpointDiscoveryUrl } from "../condition/client/CheckDiscEndpointDiscoveryUrl.ts";
import { CheckDiscEndpointIssuer } from "../condition/client/CheckDiscEndpointIssuer.ts";
import { CheckDiscEndpointIssuerIsValidUrl } from "../condition/client/CheckDiscEndpointIssuerIsValidUrl.ts";
import { CheckDiscEndpointRegistrationEndpoint } from "../condition/client/CheckDiscEndpointRegistrationEndpoint.ts";
import { CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256 } from "../condition/client/CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256.ts";
import { CheckDiscEndpointRequestParameterSupported } from "../condition/client/CheckDiscEndpointRequestParameterSupported.ts";
import { CheckDiscEndpointRequestUriParameterSupported } from "../condition/client/CheckDiscEndpointRequestUriParameterSupported.ts";
import { CheckDiscEndpointLocalesCanonicalCasing } from "../condition/client/CheckDiscEndpointLocalesCanonicalCasing.ts";
import { CheckDiscEndpointLocalesSyntax } from "../condition/client/CheckDiscEndpointLocalesSyntax.ts";
import { CheckDiscEndpointScopesSupportedSyntax } from "../condition/client/CheckDiscEndpointScopesSupportedSyntax.ts";
import { CheckForUnexpectedParametersInServerMetadata } from "../condition/client/CheckForUnexpectedParametersInServerMetadata.ts";
import { ValidateServerMetadataAgainstSchema } from "../condition/client/ValidateServerMetadataAgainstSchema.ts";
import { CheckDiscEndpointUserinfoEndpoint } from "../condition/client/CheckDiscEndpointUserinfoEndpoint.ts";
import { CheckDiscoveryEndpointReturnedJsonContentType } from "../condition/client/CheckDiscoveryEndpointReturnedJsonContentType.ts";
import { EnsureDiscoveryEndpointResponseStatusCodeIs200 } from "../condition/client/EnsureDiscoveryEndpointResponseStatusCodeIs200.ts";
import { EnsureServerConfigurationCodeChallengeMethodsSupportedIsAnArray } from "../condition/client/EnsureServerConfigurationCodeChallengeMethodsSupportedIsAnArray.ts";
import { FetchServerKeys } from "../condition/client/FetchServerKeys.ts";
import { GetDynamicServerConfiguration } from "../condition/client/GetDynamicServerConfiguration.ts";
import { OIDCCCheckDiscEndpointClaimsSupported } from "../condition/client/OIDCCCheckDiscEndpointClaimsSupported.ts";
import { OIDCCCheckDiscEndpointGrantTypesSupported } from "../condition/client/OIDCCCheckDiscEndpointGrantTypesSupported.ts";
import { OIDCCCheckDiscEndpointGrantTypesSupportedDynamic } from "../condition/client/OIDCCCheckDiscEndpointGrantTypesSupportedDynamic.ts";
import { OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported } from "../condition/client/OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported.ts";
import { OIDCCCheckDiscEndpointResponseTypesSupported } from "../condition/client/OIDCCCheckDiscEndpointResponseTypesSupported.ts";
import { OIDCCCheckDiscEndpointResponseTypesSupportedDynamic } from "../condition/client/OIDCCCheckDiscEndpointResponseTypesSupportedDynamic.ts";
import { OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported } from "../condition/client/OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported.ts";
import { CheckRequiredOidcDiscoveryMetadataSequence } from "../sequence/CheckRequiredOidcDiscoveryMetadataSequence.ts";
import { ValidateJwksSequence } from "../sequence/ValidateJwksSequence.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ServerMetadata } from "../variant/ServerMetadata.ts";
import {
	AbstractTestModule,
	ConditionResult,
	Status,
	type ConditionSequence,
	type JsonObject,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";

// Corresponds to OP-Discovery-* tests
export class OIDCCDiscoveryEndpointVerification extends AbstractTestModule {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-discovery-endpoint-verification",
		displayName: "OIDCC: Discovery Endpoint Verification",
		summary:
			"This test ensures that the server's configurations (including scopes, response_types, grant_types etc) contains values required by the specifications",
		profile: "OIDCC",
		configurationFields: ["server.discoveryUrl"],
	};

	static override variants: ModuleVariantMetadata = {
		parameters: [ServerMetadata, ClientRegistration],
		notApplicable: [{ parameter: ServerMetadata, values: ["static"] }],
	};

	override async configure(
		config: JsonObject,
		baseUrl: string,
		_externalUrlOverride: string,
		baseMtlsUrl: string,
	): Promise<void> {
		this.env.putString("base_url", baseUrl);
		this.env.putString("base_mtls_url", baseMtlsUrl);
		this.env.putObject("config", config);

		// Includes check-http-response assertion (OIDC test)
		await this.callAndStopOnFailure(GetDynamicServerConfiguration);
		await this.callAndContinueOnFailure(
			EnsureDiscoveryEndpointResponseStatusCodeIs200,
			ConditionResult.FAILURE,
			"OIDCD-4",
		);
		await this.callAndContinueOnFailure(
			CheckDiscoveryEndpointReturnedJsonContentType,
			ConditionResult.FAILURE,
			"OIDCD-4",
		);

		await this.setStatus(Status.CONFIGURED);
		this.fireSetupDone();
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);
		await this.performEndpointVerification();
		await this.fireTestFinished();
	}

	protected async performEndpointVerification(): Promise<void> {
		await this.callAndContinueOnFailure(CheckDiscEndpointDiscoveryUrl, ConditionResult.FAILURE);

		await this.callAndContinueOnFailure(CheckDiscEndpointIssuer, ConditionResult.FAILURE, "OIDCD-4.3", "OIDCD-7.2");
		await this.callAndContinueOnFailure(CheckDiscEndpointIssuerIsValidUrl, ConditionResult.FAILURE, "RFC8414-2");

		await this.callAndContinueOnFailure(
			ValidateServerMetadataAgainstSchema,
			ConditionResult.FAILURE,
			"OIDCD-3",
			"RFC8414-2",
		);
		await this.callAndContinueOnFailure(
			CheckForUnexpectedParametersInServerMetadata,
			ConditionResult.WARNING,
			"OIDCD-3",
			"RFC8414-2",
		);

		// Includes verify-op-endpoints-use-https assertion (OIDC test) for each endpoint tested,
		// verify-id_token_signing-algorithm-is-supported and providerinfo-has-jwks_uri
		await this.call(this.requiredOidcMetadataChecks());

		await this.call(
			this.condition(OIDCCCheckDiscEndpointUserinfoSigningAlgValuesSupported)
				.skipIfElementMissing("server", "userinfo_signing_alg_values_supported")
				.onFail(ConditionResult.FAILURE)
				.onSkip(ConditionResult.INFO)
				.requirement("OIDCD-3")
				.dontStopOnFailure(),
		);

		await this.call(
			this.condition(CheckDiscEndpointUserinfoEndpoint)
				.skipIfElementMissing("server", "userinfo_endpoint")
				.onFail(ConditionResult.FAILURE)
				.onSkip(ConditionResult.WARNING) // userinfo endpoint is recommended in the spec
				.requirement("OIDCD-3")
				.dontStopOnFailure(),
		);

		// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#verify_op_has_registration_endpoint
		await this.call(
			this.condition(CheckDiscEndpointRegistrationEndpoint)
				.skipIfElementMissing("server", "registration_endpoint")
				.onFail(ConditionResult.FAILURE)
				.onSkip(ConditionResult.INFO)
				.requirement("OIDCD-3")
				.dontStopOnFailure(),
		);

		await this.callAndStopOnFailure(FetchServerKeys);
		await this.call(new ValidateJwksSequence("server_jwks", null, "server JWKS", "OIDCD-3"));

		await this.callAndContinueOnFailure(CheckDiscEndpointRequestParameterSupported, ConditionResult.INFO);

		await this.callAndContinueOnFailure(CheckDiscEndpointRequestUriParameterSupported, ConditionResult.INFO);

		await this.call(
			this.condition(CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256)
				.skipIfElementMissing("server", "request_object_signing_alg_values_supported")
				.onFail(ConditionResult.WARNING)
				.onSkip(ConditionResult.INFO)
				.requirement("OIDCD-3")
				.dontStopOnFailure(),
		);

		await this.callAndContinueOnFailure(CheckDiscEndpointClaimsParameterSupported, ConditionResult.INFO, "OIDCD-3");

		// Includes providerinfo-has-claims_supported assertion (OIDC test)
		// claims_supported is recommended to be present, but not required
		await this.callAndContinueOnFailure(OIDCCCheckDiscEndpointClaimsSupported, ConditionResult.WARNING, "OIDCD-3");

		if (this.getVariant(ClientRegistration) === ClientRegistration.DYNAMIC_CLIENT) {
			await this.callAndContinueOnFailure(
				OIDCCCheckDiscEndpointGrantTypesSupportedDynamic,
				ConditionResult.FAILURE,
				"OIDCD-3",
			);
		} else {
			await this.callAndContinueOnFailure(
				OIDCCCheckDiscEndpointGrantTypesSupported,
				ConditionResult.FAILURE,
				"OIDCD-3",
			);
		}

		await this.callAndContinueOnFailure(CheckDiscEndpointScopesSupportedSyntax, ConditionResult.FAILURE, "RFC6749-3.3");
		await this.callAndContinueOnFailure(CheckDiscEndpointLocalesSyntax, ConditionResult.FAILURE, "RFC8414-2");
		await this.callAndContinueOnFailure(CheckDiscEndpointLocalesCanonicalCasing, ConditionResult.WARNING, "RFC8414-2");

		// Equivalent of VerifyOPEndpointsUseHTTPS
		// https://github.com/rohe/oidctest/blob/a306ff8ccd02da456192b595cf48ab5dcfd3d15a/src/oidctest/op/check.py#L1714
		// I'm not convinced the standards actually says every endpoint (including ones not defined by OIDC) must be https,
		// but equally it seems reasonable.
		await this.callAndContinueOnFailure(CheckDiscEndpointAllEndpointsAreHttps, ConditionResult.FAILURE);

		await this.callAndContinueOnFailure(
			EnsureServerConfigurationCodeChallengeMethodsSupportedIsAnArray,
			ConditionResult.FAILURE,
			"RFC8414-2",
			"RFC7636-4.3",
		);
	}

	protected requiredOidcMetadataChecks(): ConditionSequence {
		const dynamic = this.getVariant(ClientRegistration) === ClientRegistration.DYNAMIC_CLIENT;
		return new CheckRequiredOidcDiscoveryMetadataSequence(
			dynamic ? OIDCCCheckDiscEndpointResponseTypesSupportedDynamic : OIDCCCheckDiscEndpointResponseTypesSupported,
			OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported,
		).responseTypesSupportedRequirements("OIDCD-3", dynamic ? "OIDCC-15.2" : "OIDCC-3");
	}
}

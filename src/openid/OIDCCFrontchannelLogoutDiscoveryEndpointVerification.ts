import { CheckDiscEndSessionEndpoint } from "../condition/client/CheckDiscEndSessionEndpoint.ts";
import { CheckDiscEndpointAllEndpointsAreHttps } from "../condition/client/CheckDiscEndpointAllEndpointsAreHttps.ts";
import { CheckDiscEndpointFrontchannelLogoutSessionSupported } from "../condition/client/CheckDiscEndpointFrontchannelLogoutSessionSupported.ts";
import { CheckDiscEndpointFrontchannelLogoutSupported } from "../condition/client/CheckDiscEndpointFrontchannelLogoutSupported.ts";
import { CheckDiscoveryEndpointReturnedJsonContentType } from "../condition/client/CheckDiscoveryEndpointReturnedJsonContentType.ts";
import { EnsureDiscoveryEndpointResponseStatusCodeIs200 } from "../condition/client/EnsureDiscoveryEndpointResponseStatusCodeIs200.ts";
import { GetDynamicServerConfiguration } from "../condition/client/GetDynamicServerConfiguration.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ServerMetadata } from "../variant/ServerMetadata.ts";
import {
	AbstractTestModule,
	ConditionResult,
	Status,
	type JsonObject,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_BackChannel_Discovery
// https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-BackChannel-Discovery.json
export class OIDCCFrontchannelLogoutDiscoveryEndpointVerification extends AbstractTestModule {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-frontchannel-logout-discovery-endpoint-verification",
		displayName: "OIDCC: Frontchannel Logout Discovery Endpoint Verification",
		summary:
			"This test ensures that the server's configurations contains the values required by the specifications, frontchannel_logout_supported,  frontchannel_logout_session_supported and end_session_endpoint. Certification for this profile requires that frontchannel logout session (i.e. 'sid' in the id_token & logout request) is supported.",
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
		// Equivalent of VerifyOPEndpointsUseHTTPS
		// https://github.com/rohe/oidctest/blob/a306ff8ccd02da456192b595cf48ab5dcfd3d15a/src/oidctest/op/check.py#L1714
		// I'm not convinced the standards actually says every endpoint (including ones not defined by OIDC) must be https,
		// but equally it seems reasonable. Individual endpoint checks (e.g. CheckDiscEndSessionEndpoint) also check
		// the relevant urls are https.
		await this.callAndContinueOnFailure(CheckDiscEndpointAllEndpointsAreHttps, ConditionResult.FAILURE);
		await this.callAndContinueOnFailure(
			CheckDiscEndpointFrontchannelLogoutSupported,
			ConditionResult.FAILURE,
			"OIDCFCL-2",
		);
		// It's optional in the spec, but for certification OPs must support the session id (sid) in the id_token / logout request, due to "the mess with cookies and SameSite"
		await this.callAndContinueOnFailure(
			CheckDiscEndpointFrontchannelLogoutSessionSupported,
			ConditionResult.FAILURE,
			"OIDCFCL-2",
		);
		// python didn't check this; I have no idea why not, it's definitely needed to complete the test...
		await this.callAndContinueOnFailure(
			CheckDiscEndSessionEndpoint,
			ConditionResult.FAILURE,
			"OIDCBCL-3",
			"OIDCRIL-2.1",
		);
	}
}

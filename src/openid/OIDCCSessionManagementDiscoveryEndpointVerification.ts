import { CheckDiscCheckSessionIframe } from "../condition/client/CheckDiscCheckSessionIframe.ts";
import { CheckDiscEndSessionEndpoint } from "../condition/client/CheckDiscEndSessionEndpoint.ts";
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

// Corresponds to https://www.heenan.me.uk/~joseph/2020-06-05-test_desc_op.html#OP_Session_Discovery
// https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-Session-Discovery.json
export class OIDCCSessionManagementDiscoveryEndpointVerification extends AbstractTestModule {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-session-management-discovery-endpoint-verification",
		displayName: "OIDCC: Session Management Discovery Endpoint Verification",
		summary:
			"This test ensures that the server's configurations contains the values required by the specifications, check_session_iframe and end_session_endpoint.",
		profile: "OIDCC",
		configurationFields: ["server.discoveryUrl"],
	};

	static override variants: ModuleVariantMetadata = {
		parameters: [ServerMetadata, ClientRegistration],
		notApplicable: [{ parameter: ServerMetadata, values: ["static"] }],
	};

	override async configure(
		config: JsonObject,
		_baseUrl: string,
		_externalUrlOverride: string,
		_baseMtlsUrl: string,
	): Promise<void> {
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
		await this.callAndContinueOnFailure(CheckDiscCheckSessionIframe, ConditionResult.FAILURE, "OIDCSM-3.3");
		await this.callAndContinueOnFailure(CheckDiscEndSessionEndpoint, ConditionResult.FAILURE, "OIDCRIL-2.1");
	}
}

import { AddFragmentToRedirectUri } from "../condition/client/AddFragmentToRedirectUri.ts";
import { CallDynamicRegistrationEndpoint } from "../condition/client/CallDynamicRegistrationEndpoint.ts";
import { CheckErrorFromDynamicRegistrationEndpointIsInvalidRedirectUriOrInvalidClientMetadata } from "../condition/client/CheckErrorFromDynamicRegistrationEndpointIsInvalidRedirectUriOrInvalidClientMetadata.ts";
import { EnsureContentTypeJson } from "../condition/client/EnsureContentTypeJson.ts";
import { EnsureHttpStatusCodeIs400 } from "../condition/client/EnsureHttpStatusCodeIs400.ts";
import { ConditionResult, Status, type JsonObject, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCDynamicRegistrationTest } from "./AbstractOIDCCDynamicRegistrationTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_redirect_uri_RegFrag
export class OIDCCRedirectUriRegFrag extends AbstractOIDCCDynamicRegistrationTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-redirect-uri-regfrag",
		displayName: "OIDCC: Reject registration where a redirect_uri has a fragment",
		summary:
			"This test calls the dynamic registration endpoint with a redirect URI containing a fragment specifier. This should result in an error from the dynamic registration endpoint.",
		profile: "OIDCC",
	};

	protected override async onConfigure(_config: JsonObject, _baseUrl: string): Promise<void> {
		await this.callAndStopOnFailure(AddFragmentToRedirectUri);
		this.exposeEnvString("redirect_uri");
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);
		await this.configureDynamicClient();
		// No authorization flow in this test
		await this.fireTestFinished();
	}

	protected override async configureDynamicClient(): Promise<void> {
		await this.createDynamicClientRegistrationRequest();

		await this.callAndStopOnFailure(CallDynamicRegistrationEndpoint, "RFC6749-3.1.2");

		this.env.mapKey("endpoint_response", "dynamic_registration_endpoint_response");
		await this.callAndContinueOnFailure(EnsureContentTypeJson, ConditionResult.FAILURE);
		await this.callAndContinueOnFailure(EnsureHttpStatusCodeIs400, ConditionResult.FAILURE);
		await this.callAndContinueOnFailure(
			CheckErrorFromDynamicRegistrationEndpointIsInvalidRedirectUriOrInvalidClientMetadata,
			ConditionResult.WARNING,
			"OIDCR-3.3",
		);
	}

	protected override async performAuthorizationFlow(): Promise<void> {
		// Not used in this test
	}
}

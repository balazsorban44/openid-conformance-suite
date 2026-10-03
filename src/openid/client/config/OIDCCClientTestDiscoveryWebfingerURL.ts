import { TestFailureException, type PublishTestModule } from "../../../framework/index.ts";
import { AddRandomSuffixToIssuerInServerConfiguration } from "../../../condition/as/AddRandomSuffixToIssuerInServerConfiguration.ts";
import { AbstractOIDCCClientTest } from "../AbstractOIDCCClientTest.ts";

export class OIDCCClientTestDiscoveryWebfingerURL extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-discovery-webfinger-url",
		displayName: "OIDCC: Relying party test, webfinger using url syntax",
		summary:
			"The client is expected to use WebFinger (RFC7033) and " +
			"OpenID Provider Issuer Discovery to determine the location of the OpenID Provider configuration" +
			" and send a request to the .well-known/openid-configuration endpoint. " +
			" The discovery should be done using URL syntax as user input identifier. " +
			" The resource URI MUST have the following value: " +
			"'https://HOST/YOUR_TEST_ALIAS/oidcc-client-test-discovery-webfinger-url' " +
			"(HOST should be the hostname:port for the suite)." +
			"Corresponds to rp-discovery-webfinger-url test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async configureServerConfiguration(): Promise<void> {
		await super.configureServerConfiguration();
		await this.callAndStopOnFailure(AddRandomSuffixToIssuerInServerConfiguration);
	}

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		if (this.receivedDiscoveryRequest) {
			await this.fireTestFinished();
			return true;
		}
		return super.finishTestIfAllRequestsAreReceived();
	}

	protected override async handleClientRequestForPath(
		requestId: string,
		path: string,
		servletResponse: unknown,
	): Promise<Response> {
		const discoveryUrl = this.env.getString("discoveryUrl") as string;
		const suffix = discoveryUrl.substring(discoveryUrl.length - (10 + ".well-known/openid-configuration".length));
		if (path.endsWith(suffix)) {
			this.receivedDiscoveryRequest = true;
			return this.handleDiscoveryEndpointRequest();
		}
		return super.handleClientRequestForPath(requestId, path, servletResponse);
	}

	protected override validateWebfingerRequestResource(resourcePrefix: string): void {
		if ("https" !== resourcePrefix) {
			throw new TestFailureException(
				this.getId(),
				"This test expects a webfinger request using URL syntax " +
					"(e.g https://example.com/test-alias/" +
					this.getName() +
					")",
			);
		}
	}
}

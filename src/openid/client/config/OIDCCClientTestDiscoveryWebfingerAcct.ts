import { TestFailureException, type PublishTestModule } from "../../../framework/index.ts";
import { AddRandomSuffixToIssuerInServerConfiguration } from "../../../condition/as/AddRandomSuffixToIssuerInServerConfiguration.ts";
import { AbstractOIDCCClientTest } from "../AbstractOIDCCClientTest.ts";

export class OIDCCClientTestDiscoveryWebfingerAcct extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-discovery-webfinger-acct",
		displayName: "OIDCC: Relying party test, webfinger using acct syntax",
		summary:
			"The client is expected to use WebFinger (RFC7033) and " +
			"OpenID Provider Issuer Discovery to determine the location of the OpenID Provider configuration" +
			" and send a request to the .well-known/openid-configuration endpoint. " +
			"The discovery should be done using acct URI syntax as user input identifier. " +
			" Note that the acct value must adhere to the pattern " +
			"'acct:YOUR_TEST_ALIAS.oidcc-client-test-discovery-webfinger-acct@HOST' " +
			"(HOST should be the hostname:port for the suite but it's not validated by the suite)." +
			"Corresponds to rp-discovery-webfinger-acct test in the old test suite.",
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
		if ("acct" !== resourcePrefix) {
			throw new TestFailureException(this.getId(), "This test expects a webfinger request using acct syntax");
		}
	}
}

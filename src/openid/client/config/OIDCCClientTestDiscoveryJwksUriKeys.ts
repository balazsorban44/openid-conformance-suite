import { RandomStringUtils, TestFailureException, type PublishTestModule } from "../../../framework/index.ts";
import { AddRandomJwksUriToServerConfiguration } from "../../../condition/as/AddRandomJwksUriToServerConfiguration.ts";
import { AbstractOIDCCClientTest } from "../AbstractOIDCCClientTest.ts";

export class OIDCCClientTestDiscoveryJwksUriKeys extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-discovery-jwks-uri-keys",
		displayName: "OIDCC: Relying party discovery test, jwks_uri support",
		summary:
			"The client is expected to retrieve OpenID Provider Configuration Information " +
			"and send a request to jwks_uri obtained from OP configuration." +
			"The jwks_uri endpoint changes every execution and retrieving the configuration is a requirement." +
			"Corresponds to rp-discovery-jwks_uri-keys test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	/**
	 * We will append this random value to the end of the jwks uri to make it random per test
	 */
	private randomJwksUriSuffix = RandomStringUtils.nextAlphabetic(10);

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		if (this.receivedDiscoveryRequest && this.receivedJwksRequest) {
			await this.fireTestFinished();
			return true;
		}
		return super.finishTestIfAllRequestsAreReceived();
	}

	protected override async configureServerConfiguration(): Promise<void> {
		await super.configureServerConfiguration();
		this.env.putString("random_jwks_uri_suffix", this.randomJwksUriSuffix);
		await this.callAndStopOnFailure(AddRandomJwksUriToServerConfiguration);
	}

	protected override getJwksPath(): string {
		return "jwks" + this.randomJwksUriSuffix;
	}

	protected override checkIfDiscoveryCalled(path: string): void {
		if (!this.receivedDiscoveryRequest) {
			throw new TestFailureException(
				this.getId(),
				"Got unexpected HTTP call to " + path + " before the discovery endpoint call",
			);
		}
	}

	protected override checkIfJWKCalled(path: string): void {
		if (!this.receivedJwksRequest) {
			throw new TestFailureException(
				this.getId(),
				"Got unexpected HTTP call to " + path + " before the jwks endpoint call",
			);
		}
	}
}

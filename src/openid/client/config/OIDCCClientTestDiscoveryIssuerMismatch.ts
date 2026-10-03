import { TestFailureException, type PublishTestModule } from "../../../framework/index.ts";
import { ChangeIssuerInServerConfigurationToBeInvalid } from "../../../condition/as/ChangeIssuerInServerConfigurationToBeInvalid.ts";
import { AbstractOIDCCClientTest } from "../AbstractOIDCCClientTest.ts";

export class OIDCCClientTestDiscoveryIssuerMismatch extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-discovery-issuer-mismatch",
		displayName: "OIDCC: Relying party OpenID discovery issuer mismatch",
		summary:
			"The client is expected to retrieve OpenID Provider Configuration Information " +
			"from the .well-known/openid-configuration endpoint " +
			"and detect that the issuer in the provider configuration does not match the one returned by WebFinger." +
			"Corresponds to rp-discovery-issuer-not-matching-config test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async handleDiscoveryEndpointRequest(): Promise<Response> {
		await this.callAndStopOnFailure(ChangeIssuerInServerConfigurationToBeInvalid);
		const returnValue = await super.handleDiscoveryEndpointRequest();
		this.startWaitingForTimeout();
		return returnValue;
	}

	protected override async handleAuthorizationEndpointRequest(_requestId: string): Promise<Response> {
		throw new TestFailureException(
			this.getId(),
			"The client is expected to detect the issuer mismatch and stop" +
				" the flow after fetching OpenID Provider configuration.",
		);
	}
}

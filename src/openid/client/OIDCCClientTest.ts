import { ConditionResult, type PublishTestModule } from "../../framework/index.ts";
import { CheckForInvalidCharsInNonce } from "../../condition/as/CheckForInvalidCharsInNonce.ts";
import { CheckNonceMaximumLength } from "../../condition/as/CheckNonceMaximumLength.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

/**
 * the default happy path test
 */
export class OIDCCClientTest extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test",
		displayName: "OIDCC: Relying party test, success case",
		summary:
			"The client is expected to make an authentication request " +
			"(also a token request and a userinfo request where applicable)" +
			"using the selected response_type and other configuration options. ",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async extractNonceFromAuthorizationEndpointRequestParameters(): Promise<void> {
		await super.extractNonceFromAuthorizationEndpointRequestParameters();

		await this.skipIfMissing(
			null,
			["nonce"],
			ConditionResult.INFO,
			CheckForInvalidCharsInNonce,
			ConditionResult.WARNING,
		);
		await this.skipIfMissing(null, ["nonce"], ConditionResult.INFO, CheckNonceMaximumLength, ConditionResult.WARNING);
	}
}

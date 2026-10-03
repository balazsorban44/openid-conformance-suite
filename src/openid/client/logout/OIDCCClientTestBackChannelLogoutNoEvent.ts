import { ConditionResult, type PublishTestModule } from "../../../framework/index.ts";
import { RemoveEventsClaimFromLogoutToken } from "../../../condition/as/logout/RemoveEventsClaimFromLogoutToken.ts";
import { EnsureBackChannelLogoutUriResponseStatusCodeIs400 } from "../../../condition/as/logout/EnsureBackChannelLogoutUriResponseStatusCodeIs400.ts";
import { AbstractOIDCCClientBackChannelLogoutTest } from "./AbstractOIDCCClientBackChannelLogoutTest.ts";

export class OIDCCClientTestBackChannelLogoutNoEvent extends AbstractOIDCCClientBackChannelLogoutTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-rp-backchannel-rpinitlogout-no-event",
		displayName: "OIDCC: Relying party test, back channel logout request without an events claim.",
		summary:
			"The client is expected to make an authorization request " +
			"(also a token request and a optionally a userinfo request when applicable)," +
			" then the RP terminates the session by calling the end_session_endpoint (RP-Initiated Logout)," +
			" at this point the conformance suite will send a back channel logout request without an events claim " +
			" in the logout_token which should be rejected, " +
			" then the RP is expected to handle post logout URI redirect." +
			" Corresponds to rp-backchannel-rpinitlogout-lt-no-event in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async customizeLogoutTokenClaims(): Promise<void> {
		await this.callAndStopOnFailure(RemoveEventsClaimFromLogoutToken, "OIDCBCL-2.4");
	}

	protected override async validateBackChannelLogoutResponse(): Promise<void> {
		await super.validateBackChannelLogoutResponse();
		await this.callAndContinueOnFailure(
			EnsureBackChannelLogoutUriResponseStatusCodeIs400,
			ConditionResult.FAILURE,
			"OIDCBCL-2.8",
		);
	}
}

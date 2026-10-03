import { ConditionResult, type PublishTestModule } from "../../../framework/index.ts";
import { OIDCCSignLogoutTokenWithAlgNone } from "../../../condition/as/logout/OIDCCSignLogoutTokenWithAlgNone.ts";
import { EnsureBackChannelLogoutUriResponseStatusCodeIs400 } from "../../../condition/as/logout/EnsureBackChannelLogoutUriResponseStatusCodeIs400.ts";
import { AbstractOIDCCClientBackChannelLogoutTest } from "./AbstractOIDCCClientBackChannelLogoutTest.ts";

export class OIDCCClientTestBackChannelLogoutAlgNone extends AbstractOIDCCClientBackChannelLogoutTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-rp-backchannel-rpinitlogout-alg-none",
		displayName: "OIDCC: Relying party test, back channel logout request signed using alg 'none'.",
		summary:
			"The client is expected to make an authorization request " +
			"(also a token request and a optionally a userinfo request when applicable)," +
			" then terminate the session by calling the end_session_endpoint (RP-Initiated Logout)," +
			" at this point the conformance suite will send a back channel logout request containing " +
			" a logout_token signed using alg 'none' which should be rejected, " +
			" then the RP is expected to handle post logout URI redirect." +
			" Corresponds to rp-backchannel-rpinitlogout-lt-alg-none in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async signLogoutToken(): Promise<void> {
		await this.callAndStopOnFailure(OIDCCSignLogoutTokenWithAlgNone);
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

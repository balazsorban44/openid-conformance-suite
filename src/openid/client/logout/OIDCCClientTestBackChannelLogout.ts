import { ConditionResult, type PublishTestModule } from "../../../framework/index.ts";
import { EnsureBackChannelLogoutUriResponseStatusCodeIs200 } from "../../../condition/as/logout/EnsureBackChannelLogoutUriResponseStatusCodeIs200.ts";
import { AbstractOIDCCClientBackChannelLogoutTest } from "./AbstractOIDCCClientBackChannelLogoutTest.ts";

export class OIDCCClientTestBackChannelLogout extends AbstractOIDCCClientBackChannelLogoutTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-rp-backchannel-rpinitlogout",
		displayName: "OIDCC: Relying party test, back channel logout.",
		summary:
			"The client is expected to make an authorization request " +
			"(also a token request and a optionally a userinfo request when applicable)," +
			" then terminate the session by calling the end_session_endpoint (RP-Initiated Logout)," +
			" at this point the conformance suite will send a back channel logout request to the RP, " +
			" then the RP is expected to handle post logout URI redirect." +
			" Corresponds to rp-backchannel-rpinitlogout in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async validateBackChannelLogoutResponse(): Promise<void> {
		await super.validateBackChannelLogoutResponse();
		await this.callAndContinueOnFailure(
			EnsureBackChannelLogoutUriResponseStatusCodeIs200,
			ConditionResult.FAILURE,
			"OIDCBCL-2.8",
		);
	}
}

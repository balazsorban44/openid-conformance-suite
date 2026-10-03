/**
 * OpenID Connect Core: RP Initiated Logout RP Certification Profile, RP tests (upstream
 * openid/client/logout/plan/OIDCCClientRPInitiatedLogoutRPBasicTestPlan.java).
 *
 * The plan fixes response_type=code; the user selects client_auth_type, response_mode, request_type and
 * client_registration (CONFORMANCE_VARIANT or the CI project).
 *
 * The RP logs in, then sends its user agent to the end_session_endpoint (RP-Initiated Logout). The OP posts a
 * logout_token to the RP's backchannel_logout_uri and/or renders a page loading its frontchannel_logout_uri in an
 * iframe (whichever the client registered; both when it registered both), then redirects to the
 * post_logout_redirect_uri.
 *
 *   CONFORMANCE_PROJECT=rp-rp-initiated-logout pnpm test tests/rp/rp-initiated-logout.spec.ts
 */
import * as logout from "../../src/rp/logout.ts";
import { test } from "../fixtures.ts";

test.describe("oidcc-client-rp-initiated-logout-rp-basic", () => {
	test.use({
		plan: { name: "oidcc-client-rp-initiated-logout-rp-basic", variant: { response_type: "code" } },
	});

	// upstream: openid/client/logout/OIDCCClientTestRPInitLogout.java (rp-init-logout)
	test("oidcc-client-test-rp-init-logout: the RP logs out at the end_session_endpoint and handles the post logout redirect", async ({
		rp,
	}) => {
		const op = await rp.start(logout.logoutTestOptions({ channels: "registered" }));
		const client = rp.driveClient();
		await op.clientRegistered();
		// the RP logs in (token and userinfo requests are not required)
		await op.expect("authorization");
		// RP-initiated logout: the OP calls the back-channel logout uri and/or renders the front-channel logout page
		const endSession = await op.expect("end_session");
		if (endSession.frontChannelLogoutUrl != null) {
			// the front-channel logout page loaded the RP's frontchannel_logout_uri
			await op.expect("frontchannel_logout_callback");
		}
		await client;
	});

	// upstream: openid/client/logout/OIDCCClientTestRPInitLogoutInvalidState.java (rp-init-logout-other-state)
	test("oidcc-client-test-rp-init-logout-other-state: the RP handles a post logout redirect with a state it did not send", async ({
		rp,
	}) => {
		const op = await rp.start(
			logout.logoutTestOptions({
				channels: "registered",
				checkEndSessionRequest: (params) => {
					if (!params["state"]) {
						rp.skipTest(
							"Skipping test due to the optional state parameter not being supplied to the end_session_endpoint",
						);
					}
					logout.ensureEndSessionEndpointRequestContainsStateParameter(params);
				},
				postLogoutRedirectParams: (params) => logout.addInvalidStateToPostLogoutRedirectUriParams(params, "OIDCRIL-2"),
			}),
		);
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		// the OP redirects to the post_logout_redirect_uri with a different state
		const endSession = await op.expect("end_session");
		if (endSession.frontChannelLogoutUrl != null) {
			await op.expect("frontchannel_logout_callback");
		}
		await client;
	});

	// upstream: openid/client/logout/OIDCCClientTestRPInitLogoutNoState.java (rp-init-logout-no-state)
	test("oidcc-client-test-rp-init-logout-no-state: the RP handles a post logout redirect without the state it sent", async ({
		rp,
	}) => {
		const op = await rp.start(
			logout.logoutTestOptions({
				channels: "registered",
				checkEndSessionRequest: (params) => {
					if (!params["state"]) {
						rp.skipTest(
							"Skipping test due to the optional state parameter not being supplied to the end_session_endpoint",
						);
					}
					logout.ensureEndSessionEndpointRequestContainsStateParameter(params);
				},
				postLogoutRedirectParams: (params) => logout.removeStateFromPostLogoutRedirectUriParams(params, "OIDCRIL-2"),
			}),
		);
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		// the OP redirects to the post_logout_redirect_uri without state
		const endSession = await op.expect("end_session");
		if (endSession.frontChannelLogoutUrl != null) {
			await op.expect("frontchannel_logout_callback");
		}
		await client;
	});
});

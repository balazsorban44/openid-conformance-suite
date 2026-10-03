/**
 * OpenID Connect Core: Front Channel Logout RP Certification Profile, RP tests (upstream
 * openid/client/logout/plan/OIDCCClientFrontChannelLogoutRPBasicTestPlan.java).
 *
 * The plan fixes response_type=code; the user selects client_auth_type, response_mode, request_type and
 * client_registration (CONFORMANCE_VARIANT or the CI project).
 *
 *   CONFORMANCE_PROJECT=rp-frontchannel-logout pnpm test tests/rp/frontchannel-logout.spec.ts
 */
import * as logout from "../../src/rp/logout.ts";
import { test } from "../fixtures.ts";

test.describe("oidcc-client-front-channel-logout-rp-basic", () => {
	test.use({
		plan: { name: "oidcc-client-front-channel-logout-rp-basic", variant: { response_type: "code" } },
	});

	// upstream: openid/client/logout/OIDCCClientTestFrontChannelLogoutRPInitiated.java (rp-frontchannel-rpinitlogout)
	test("oidcc-client-test-rp-frontchannel-rpinitlogout: the RP logs out, its frontchannel_logout_uri is loaded and it handles the post logout redirect", async ({
		rp,
	}) => {
		const op = await rp.start(logout.logoutTestOptions({ channels: "front" }));
		const client = rp.driveClient();
		await op.clientRegistered();
		// the RP logs in (token and userinfo requests are not required)
		await op.expect("authorization");
		// RP-initiated logout: the OP answers with a page that loads the RP's frontchannel_logout_uri in an iframe
		await op.expect("end_session");
		// the page reports that the iframe loaded, then redirects to the post_logout_redirect_uri (whether the RP
		// really logged out cannot be seen from a cross-origin iframe; upstream marks the test for review)
		await op.expect("frontchannel_logout_callback");
		await client;
	});
});

/**
 * OpenID Connect Core: Session Management RP Certification Profile, RP tests (upstream
 * openid/client/logout/plan/OIDCCClientSessionManagementRPBasicTestPlan.java).
 *
 * The plan fixes response_type=code; the user selects client_auth_type, response_mode, request_type and
 * client_registration (CONFORMANCE_VARIANT or the CI project).
 *
 *   CONFORMANCE_PROJECT=rp-session-management pnpm test tests/rp/session-management.spec.ts
 */
import * as logout from "../../src/rp/logout.ts";
import { test } from "../fixtures.ts";

test.describe("oidcc-client-rp-session-management-rp-basic", () => {
	test.use({
		plan: { name: "oidcc-client-rp-session-management-rp-basic", variant: { response_type: "code" } },
	});

	// upstream: openid/client/logout/OIDCCClientTestSessionManagement.java (rp-init-logout-session)
	test("oidcc-client-test-session-management: the RP checks the session with the check_session_iframe before and after it logs out", async ({
		rp,
	}) => {
		const op = await rp.start(logout.logoutTestOptions({ channels: "none" }));
		const client = rp.driveClient();
		await op.clientRegistered();
		// the RP logs in (token and userinfo requests are not required); the response carries session_state
		await op.expect("authorization");
		// the RP loads the check_session_iframe and posts "client_id session_state" to it: the OP iframe answers
		// "unchanged" (any number of checks before logout is fine)
		const before = await op.expect("get_session_state");
		if (before.afterLogout) {
			throw new Error("The RP did not post a message to the check_session_iframe before it logged out");
		}
		// RP-initiated logout ends the session
		await op.expect("end_session");
		// after logout the OP iframe answers "changed"
		let after = await op.expect("get_session_state");
		while (!after.afterLogout) {
			after = await op.expect("get_session_state");
		}
		await client;
	});
});

/**
 * OpenID Connect Core Client Login Tests: Relying party 3rd party initiated login tests (upstream
 * openid/client/OIDCCClient3rdPartyInitiatedLoginTestPlan.java).
 *
 * The plan fixes no variant; the user selects them all (CONFORMANCE_VARIANT or the CI project).
 *
 * The RP registers an initiate_login_uri (OIDCC-4); the suite's own browser (the config's `browser` automation)
 * visits it with the OP's issuer, and the RP must start the authorization request from there.
 *
 *   CONFORMANCE_PROJECT=rp-3rdparty-init-login pnpm test tests/rp/3rdparty-init-login.spec.ts
 */
import { failTest } from "../../src/rp/op.ts";
import * as registration from "../../src/rp/registration.ts";
import { test } from "../fixtures.ts";

test.describe("oidcc-client-test-3rd-party-init-login-test-plan", () => {
	test.use({ plan: { name: "oidcc-client-test-3rd-party-init-login-test-plan", variant: {} } });

	// upstream: openid/client/OIDCCClient3rdPartyInitiatedLoginTest.java
	test("oidcc-client-test-3rd-party-init-login: the RP starts the login when the user is sent to its initiate_login_uri", async ({
		rp,
	}) => {
		const op = await rp.start({
			// the only client metadata check: a valid https initiate_login_uri
			validateClientMetadata: (client) => registration.validateClientInitiateLoginUri(client, "OIDCR-2"),
			// the browser visit is recorded when the navigation starts, before the RP redirects to the OP
			onAuthorizationRequest: () => {
				if (rp.browser.visited.length === 0) {
					failTest("Authorization endpoint called before user has been sent to initiate_login_uri");
				}
			},
		});
		const client = rp.driveClient();
		const registered = await op.clientRegistered();
		// the user is sent to the initiate_login_uri (with iss), the RP redirects to the authorization endpoint
		const visit = rp.browser.visit(registration.initiateLoginRedirect(registered, op.issuer));
		await op.expect("authorization");
		await op.expect("token");
		// upstream finishes the test after the userinfo request
		await op.expect("userinfo");
		await visit;
		await client;
	});
});

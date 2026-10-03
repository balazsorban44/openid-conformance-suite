/**
 * OpenID Connect Session Management: OP tests (upstream openid/OIDCCSessionManagementTestPlan.java, the
 * 'Session OP' certification profile).
 *
 * The plan fixes server_metadata=discovery, and client_auth_type=client_secret_basic and response_mode=default for
 * the logout module; the user selects response_type and client_registration. A static client must have registered
 * `<base url>/post_logout_redirect` as a post_logout_redirect_uri.
 *
 *   CONFORMANCE_PROJECT=op-session-management CONFORMANCE_TLS=1 pnpm test tests/op/session-management.spec.ts
 */
import * as discovery from "../../src/op/discovery.ts";
import * as logout from "../../src/op/logout.ts";
import * as session from "../../src/op/session.ts";
import { block, soft } from "../../src/suite/conditions.ts";
import { test } from "../fixtures.ts";

const PLAN = "oidcc-session-management-certification-test-plan";

test.describe(PLAN, () => {
	test.describe(() => {
		test.use({ plan: { name: PLAN, variant: { server_metadata: "discovery" } } });

		// upstream: openid/OIDCCSessionManagementDiscoveryEndpointVerification.java (OP-Session-Discovery)
		test("oidcc-session-management-discovery-endpoint-verification: the discovery document has an https check_session_iframe and end_session_endpoint", async ({
			conformance,
		}) => {
			const { metadata, response } = await discovery.getDynamicServerConfiguration(conformance.config);
			soft(() => discovery.ensureDiscoveryEndpointResponseStatusCodeIs200(response, "OIDCD-4"));
			soft(() => discovery.checkDiscoveryEndpointReturnedJsonContentType(response, "OIDCD-4"));

			soft(() => discovery.checkDiscCheckSessionIframe(metadata, "OIDCSM-3.3"));
			soft(() => discovery.checkDiscEndSessionEndpoint(metadata, "OIDCRIL-2.1"));
		});
	});

	test.describe(() => {
		test.use({
			plan: {
				name: PLAN,
				variant: { server_metadata: "discovery", client_auth_type: "client_secret_basic", response_mode: "default" },
			},
		});

		// upstream: openid/OIDCCSessionManagementRpInitiatedLogout.java (OP-Session-RpInitLogout)
		test("oidcc-session-management-rp-initiated-logout: the check_session_iframe reports the session unchanged after login and changed after logout", async ({
			op,
			configureClient,
		}) => {
			const postLogoutRedirectUri = logout.createPostLogoutRedirectUri(op.baseUrl, "OIDCRIL-2", "OIDCRIL-3");
			const client = await configureClient((request) =>
				logout.addPostLogoutRedirectUriToDynamicRegistrationRequest(request, postLogoutRedirectUri, "OIDCRIL-3.1"),
			);
			const userinfoUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
			discovery.checkDiscCheckSessionIframe(op.metadata, "OIDCSM-3.3");
			const { response, tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

			// the OP's check_session_iframe, asked by the suite's RP iframe in the user's browser
			const firstResult = await session.checkSessionState(
				op,
				client.client,
				session.extractSessionStateFromAuthorizationResponse(response, "OIDCSM-2"),
				"first",
			);
			soft(() => session.checkSessionResultIsUnchanged(firstResult, "OIDCSM-3.1"));

			const { state, redirect } = await block("Redirect to end session endpoint & wait for response", async () => {
				const endSessionState = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
				const request = logout.createEndSessionEndpointRequest(
					tokens.idToken.value,
					postLogoutRedirectUri,
					endSessionState,
					"OIDCRIL-2",
				);
				const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
				return { state: endSessionState, redirect: await logout.redirectToEndSessionEndpoint(op, url) };
			});

			await block("Verify frontchannel post logout redirect", () => {
				soft(() => logout.checkPostLogoutState(redirect, state, "OIDCRIL-2"));
				soft(() => logout.checkForUnexpectedParametersInPostLogoutRedirect(redirect, "OIDCRIL-2"), "warning");
			});

			// after the logout the same session_state must be reported as changed
			const secondResult = await session.checkSessionState(
				op,
				client.client,
				session.extractSessionStateFromAuthorizationResponse(response, "OIDCSM-2"),
				"second",
			);
			soft(() => session.checkSecondSessionResultIsChanged(secondResult, "OIDCSM-3.1"));
			// upstream could check the logout with a prompt=none request here, but the python suite did not
		});
	});
});

/**
 * OpenID Connect Front-Channel Logout: OP tests (upstream openid/OIDCCFrontchannelRpInitiatedLogoutTestPlan.java,
 * the 'Front-Channel Logout OP' certification profile).
 *
 * The plan fixes server_metadata=discovery, and client_auth_type=client_secret_basic and response_mode=default for
 * the logout module; the user selects response_type and client_registration. A static client must have registered
 * `<base url>/frontchannel_logout` and `<base url>/post_logout_redirect`.
 *
 *   CONFORMANCE_PROJECT=op-frontchannel-logout CONFORMANCE_TLS=1 pnpm test tests/op/frontchannel-logout.spec.ts
 */
import * as discovery from "../../src/op/discovery.ts";
import * as logout from "../../src/op/logout.ts";
import { block, soft } from "../../src/suite/conditions.ts";
import { test } from "../fixtures.ts";

const PLAN = "oidcc-frontchannel-rp-initiated-logout-certification-test-plan";

test.describe(PLAN, () => {
	test.describe(() => {
		test.use({ plan: { name: PLAN, variant: { server_metadata: "discovery" } } });

		// upstream: openid/OIDCCFrontchannelLogoutDiscoveryEndpointVerification.java
		test("oidcc-frontchannel-logout-discovery-endpoint-verification: the discovery document announces front-channel logout with sessions and an https end_session_endpoint", async ({
			conformance,
		}) => {
			const { metadata, response } = await discovery.getDynamicServerConfiguration(conformance.config);
			soft(() => discovery.ensureDiscoveryEndpointResponseStatusCodeIs200(response, "OIDCD-4"));
			soft(() => discovery.checkDiscoveryEndpointReturnedJsonContentType(response, "OIDCD-4"));

			soft(() => discovery.checkDiscEndpointAllEndpointsAreHttps(metadata));
			soft(() => discovery.checkDiscEndpointFrontchannelLogoutSupported(metadata, "OIDCFCL-2"));
			// optional in the spec, but certification requires sid in the id_token / logout request ("the mess with
			// cookies and SameSite")
			soft(() => discovery.checkDiscEndpointFrontchannelLogoutSessionSupported(metadata, "OIDCFCL-2"));
			soft(() => discovery.checkDiscEndSessionEndpoint(metadata, "OIDCBCL-3", "OIDCRIL-2.1"));
		});
	});

	test.describe(() => {
		test.use({
			plan: {
				name: PLAN,
				variant: { server_metadata: "discovery", client_auth_type: "client_secret_basic", response_mode: "default" },
			},
		});

		// upstream: openid/OIDCCFrontChannelRpInitiatedLogout.java (OP-FrontChannel-RpInitLogout)
		test("oidcc-frontchannel-rp-initiated-logout: the OP loads the frontchannel_logout_uri with iss and sid and redirects to the post_logout_redirect_uri", async ({
			op,
			configureClient,
		}) => {
			const frontchannelLogoutUri = logout.createFrontchannelLogoutUri(op.baseUrl, "OIDCFCL-2");
			const postLogoutRedirectUri = logout.createPostLogoutRedirectUri(op.baseUrl, "OIDCRIL-2", "OIDCRIL-3");
			const client = await configureClient((request) => {
				logout.addPostLogoutRedirectUriToDynamicRegistrationRequest(request, postLogoutRedirectUri, "OIDCRIL-3.1");
				logout.addFrontchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest(request, "OIDCFCL-2");
				logout.addFrontchannelLogoutUriToDynamicRegistrationRequest(request, frontchannelLogoutUri, "OIDCFCL-2");
			});
			const userinfoUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
			const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

			const { state, logoutRequest, postLogoutRedirect } = await block(
				"Redirect to end session endpoint & wait for response",
				async () => {
					const endSessionState = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
					const request = logout.createEndSessionEndpointRequest(
						tokens.idToken.value,
						postLogoutRedirectUri,
						endSessionState,
						"OIDCRIL-2",
					);
					const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
					const received = await logout.redirectToEndSessionEndpointAndWaitForLogoutRequest(op, url, "frontchannel");
					return { state: endSessionState, ...received };
				},
			);

			await block("Verify frontchannel logout request", () => {
				soft(
					() => logout.checkForUnexpectedParametersInFrontchannelLogoutRequest(logoutRequest, "OIDCFCL-2"),
					"warning",
				);
				soft(() => logout.validateFrontchannelLogoutIss(logoutRequest, op.metadata, "OIDCFCL-2"));
				soft(() =>
					logout.checkIdTokenSidMatchesFrontChannelLogoutRequest(
						tokens.idToken,
						logoutRequest,
						"OIDCFCL-2",
						"OIDCFCL-3",
					),
				);
			});

			await block("Verify frontchannel post logout redirect", () => {
				soft(() => logout.checkPostLogoutState(postLogoutRedirect, state, "OIDCRIL-2"));
				soft(() => logout.checkForUnexpectedParametersInPostLogoutRedirect(postLogoutRedirect, "OIDCRIL-2"), "warning");
			});

			// a prompt=none authorization request must now fail: the user is logged out
			await logout.verifyLoggedOutWithPromptNone(op, client);
		});
	});
});

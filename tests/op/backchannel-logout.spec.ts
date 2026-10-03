/**
 * OpenID Connect Back-Channel Logout: OP tests (upstream openid/OIDCCBackchannelRpInitiatedLogoutTestPlan.java, the
 * 'Back-Channel Logout OP' certification profile).
 *
 * The plan fixes server_metadata=discovery, and client_auth_type=client_secret_basic and response_mode=default for
 * the logout module; the user selects response_type and client_registration. The OP posts the logout token to the
 * suite's backchannel_logout_uri, which must be https: run with CONFORMANCE_TLS=1 (`openid-conformance ci` does). A
 * static client must have registered `<base url>/backchannel_logout` and `<base url>/post_logout_redirect`.
 *
 *   CONFORMANCE_PROJECT=op-backchannel-logout CONFORMANCE_TLS=1 pnpm test tests/op/backchannel-logout.spec.ts
 */
import * as discovery from "../../src/op/discovery.ts";
import * as logout from "../../src/op/logout.ts";
import { block, skipped, soft } from "../../src/suite/conditions.ts";
import { test } from "../fixtures.ts";

const PLAN = "oidcc-backchannel-rp-initiated-logout-certification-test-plan";

test.describe(PLAN, () => {
	test.describe(() => {
		test.use({ plan: { name: PLAN, variant: { server_metadata: "discovery" } } });

		// upstream: openid/OIDCCBackchannelLogoutDiscoveryEndpointVerification.java (OP-BackChannel-Discovery)
		test("oidcc-backchannel-logout-discovery-endpoint-verification: the discovery document announces back-channel logout with sessions and an https end_session_endpoint", async ({
			conformance,
		}) => {
			const { metadata } = await discovery.getDynamicServerConfiguration(conformance.config);
			soft(() => discovery.checkDiscEndpointAllEndpointsAreHttps(metadata));
			soft(() => discovery.checkDiscEndpointBackchannelLogoutSupported(metadata, "OIDCBCL-2.1"));
			// optional in the spec, but certification requires sid in the id_token / logout token ("the mess with
			// cookies and SameSite")
			soft(() => discovery.checkDiscEndpointBackchannelLogoutSessionSupported(metadata, "OIDCBCL-2.1"));
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

		// upstream: openid/OIDCCBackChannelRpInitiatedLogout.java (OP-BackChannel-RpInitLogout)
		test("oidcc-backchannel-rp-initiated-logout: the OP posts a valid logout token to the backchannel_logout_uri and redirects to the post_logout_redirect_uri", async ({
			op,
			configureClient,
		}) => {
			const backchannelLogoutUri = logout.createBackchannelLogoutUri(op.baseUrl, "OIDCBCL-2.2");
			const postLogoutRedirectUri = logout.createPostLogoutRedirectUri(op.baseUrl, "OIDCRIL-2", "OIDCRIL-3");
			const client = await configureClient((request) => {
				logout.addPostLogoutRedirectUriToDynamicRegistrationRequest(request, postLogoutRedirectUri, "OIDCRIL-3.1");
				logout.addBackchannelLogoutSessionRequiredTrueToDynamicRegistrationRequest(request, "OIDCBCL-2.2");
				logout.addBackchannelLogoutUriToDynamicRegistrationRequest(request, backchannelLogoutUri, "OIDCBCL-2.2");
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
					const received = await logout.redirectToEndSessionEndpointAndWaitForLogoutRequest(op, url, "backchannel");
					return { state: endSessionState, ...received };
				},
			);

			await block("Verify backchannel logout request", async () => {
				// a mixture of must & recommended in BCP195, which is not a normative reference of OIDCC: warnings only
				soft(() => logout.ensureIncomingTls12WithSecureCipherOrTls13(logoutRequest, "BCP195-3.1.1"), "warning");
				soft(() => logout.ensureIncomingTls13(logoutRequest, "RFC9325-3.1.1"), "warning");
				if (client.keys == null) {
					skipped(
						"ValidateLogoutTokenFromBackchannelLogoutRequestEncryption",
						{ object: "client_jwks" },
						"OIDCBCL-2.4",
					);
				} else {
					const clientJwks = client.keys.jwks;
					soft(
						() =>
							logout.validateLogoutTokenFromBackchannelLogoutRequestEncryption(
								logoutRequest,
								clientJwks,
								"OIDCBCL-2.4",
							),
						"warning",
					);
				}
				const logoutToken = await logout.extractLogoutTokenFromBackchannelLogoutRequest(logoutRequest, "OIDCBCL-2.5");
				soft(
					() => logout.checkForUnexpectedParametersInBackchannelLogoutRequest(logoutRequest, "OIDCBCL-2.5"),
					"warning",
				);
				await soft(() => logout.validateLogoutTokenSignature(logoutToken, op.jwks, "OIDCBCL-2.4"));
				soft(() => logout.validateLogoutTokenClaims(logoutToken, op.metadata, client.client, "OIDCBCL-2.4"));
				if (logoutToken.claims["sub"] == null) {
					skipped("CheckIdTokenSubMatchesLogoutToken", { element: ["logout_token", "claims.sub"] }, "OIDCBCL-2.4");
				} else {
					soft(() => logout.checkIdTokenSubMatchesLogoutToken(tokens.idToken, logoutToken, "OIDCBCL-2.4"));
				}
				if (logoutToken.claims["sid"] == null) {
					skipped("CheckIdTokenSidMatchesLogoutToken", { element: ["logout_token", "claims.sid"] }, "OIDCBCL-2.4");
				} else {
					soft(() => logout.checkIdTokenSidMatchesLogoutToken(tokens.idToken, logoutToken, "OIDCBCL-2.4"));
				}
				soft(() => logout.checkLogoutTokenNoNonce(logoutToken, "OIDCBCL-2.4"));
				soft(() => logout.checkLogoutTokenHasSubOrSid(logoutToken, "OIDCBCL-2.4"));
			});

			await block("Verify frontchannel post logout redirect", () => {
				soft(() => logout.checkPostLogoutState(postLogoutRedirect, state, "OIDCRIL-2"));
				soft(() => logout.checkForUnexpectedParametersInPostLogoutRedirect(postLogoutRedirect, "OIDCRIL-3"), "warning");
			});

			// a prompt=none authorization request must now fail: the user is logged out
			await logout.verifyLoggedOutWithPromptNone(op, client);
		});
	});
});

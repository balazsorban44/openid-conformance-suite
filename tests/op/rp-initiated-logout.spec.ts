/**
 * OpenID Connect RP-Initiated Logout: OP tests (upstream openid/OIDCCRpInitiatedLogoutTestPlan.java, the
 * 'RP-Initiated OP' certification profile).
 *
 * The plan fixes server_metadata=discovery, and client_auth_type=client_secret_basic and response_mode=default for the
 * logout modules; the user selects response_type and client_registration (CONFORMANCE_VARIANT or the CI project). A
 * static client must have registered `<base url>/post_logout_redirect` as a post_logout_redirect_uri.
 *
 *   CONFORMANCE_PROJECT=op-rp-initiated-logout CONFORMANCE_TLS=1 pnpm test tests/op/rp-initiated-logout.spec.ts
 */
import * as discovery from "../../src/op/discovery.ts";
import * as logout from "../../src/op/logout.ts";
import type { Op } from "../../src/op/op.ts";
import * as registration from "../../src/op/registration.ts";
import type { RegisteredClient } from "../../src/op/registration.ts";
import { block, soft } from "../../src/suite/conditions.ts";
import { test, type ConfigureClient } from "../fixtures.ts";

const PLAN = "oidcc-rp-initiated-logout-certification-test-plan";

/**
 * The client with the suite's post_logout_redirect_uri registered, and the userinfo endpoint as protected resource.
 *
 * upstream: AbstractOIDCCRpInitiatedLogout.configureClient / createDynamicClientRegistrationRequest +
 * AbstractOIDCCServerTest.configureProtectedResourceUrl
 */
async function configureLogoutClient(
	op: Op,
	configureClient: ConfigureClient,
): Promise<{ client: RegisteredClient; postLogoutRedirectUri: string; userinfoUrl: string }> {
	const postLogoutRedirectUri = logout.createPostLogoutRedirectUri(op.baseUrl, "OIDCRIL-2", "OIDCRIL-3");
	const client = await configureClient({
		customize: (request) =>
			logout.addPostLogoutRedirectUriToDynamicRegistrationRequest(request, postLogoutRedirectUri, "OIDCRIL-3.1"),
	});
	const userinfoUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
	return { client, postLogoutRedirectUri, userinfoUrl };
}

test.describe(PLAN, () => {
	test.describe(() => {
		test.use({ plan: { name: PLAN, variant: { server_metadata: "discovery" } } });

		// upstream: openid/OIDCCRpInitiatedLogoutDiscoveryEndpointVerification.java
		test("oidcc-rp-initiated-logout-discovery-endpoint-verification: the discovery document has an https end_session_endpoint", async ({
			conformance,
		}) => {
			const { metadata } = await discovery.getDynamicServerConfiguration(conformance.config);
			// the equivalent of the python suite's VerifyOPEndpointsUseHTTPS
			soft(() => discovery.checkDiscEndpointAllEndpointsAreHttps(metadata));
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

		// upstream: openid/OIDCCRpInitiatedLogout.java (OP-RpInitLogout)
		test("oidcc-rp-initiated-logout: the OP logs the user out and redirects to the post_logout_redirect_uri with the state", async ({
			op,
			configureClient,
		}) => {
			const { client, postLogoutRedirectUri, userinfoUrl } = await configureLogoutClient(op, configureClient);
			const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

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

			// a prompt=none authorization request must now fail: the user is logged out
			await logout.verifyLoggedOutWithPromptNone(op, client);
		});

		// upstream: openid/OIDCCRpInitiatedLogoutNoState.java (OP-RpInitLogout-No-state)
		test("oidcc-rp-initiated-logout-no-state: without a state the OP redirects to the post_logout_redirect_uri without one", async ({
			op,
			configureClient,
		}) => {
			const { client, postLogoutRedirectUri, userinfoUrl } = await configureLogoutClient(op, configureClient);
			const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

			const redirect = await block("Redirect to end session endpoint & wait for response", async () => {
				const state = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
				const request = logout.createEndSessionEndpointRequest(
					tokens.idToken.value,
					postLogoutRedirectUri,
					state,
					"OIDCRIL-2",
				);
				logout.removeStateFromEndSessionEndpointRequest(request);
				const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
				return await logout.redirectToEndSessionEndpoint(op, url);
			});

			await block("Verify frontchannel post logout redirect", () => {
				soft(() => logout.checkNoPostLogoutState(redirect, "OIDCRIL-2"));
				soft(() => logout.checkForUnexpectedParametersInPostLogoutRedirect(redirect, "OIDCRIL-3"), "warning");
			});

			await logout.verifyLoggedOutWithPromptNone(op, client);
		});

		// upstream: openid/OIDCCRpInitiatedLogoutBadIdTokenHint.java (OP-RpInitLogout-Wrong-id_token_hint)
		test("oidcc-rp-initiated-logout-bad-id-token-hint: an id_token_hint the OP did not issue is not redirected back for", async ({
			op,
			configureClient,
		}) => {
			const { client, postLogoutRedirectUri, userinfoUrl } = await configureLogoutClient(op, configureClient);
			// the fake id_token is signed with the client's key; a client without keys uses its secret
			const clientJwks = client.keys?.jwks ?? registration.generateJWKsFromClientSecret(client.client);
			await logout.performAuthorizationFlow(op, client, userinfoUrl);

			const fakeIdToken = await logout.signFakeIdToken(
				logout.generateFakeIdTokenClaims(op.metadata, client.client),
				clientJwks,
			);
			await block("Redirect to end session endpoint & wait for response", async () => {
				const state = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
				const request = logout.createEndSessionEndpointRequest(fakeIdToken, postLogoutRedirectUri, state, "OIDCRIL-2");
				const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
				// an error page, or a page asking the user whether to log out: a screenshot for review
				const errorPage = logout.expectInvalidIdTokenHintErrorPage("OIDCRIL-2");
				await logout.redirectToEndSessionEndpointExpectingNoRedirect(
					op,
					url,
					errorPage,
					"OP has incorrectly called the registered post_logout_redirect_uri even though an invalid id_token_hint was provided.",
				);
			});
		});

		// upstream: openid/OIDCCRpInitiatedLogoutModifiedIdTokenHint.java (OP-RpInitLogout-Modified-id_token_hint)
		test("oidcc-rp-initiated-logout-modified-id-token-hint: an id_token_hint changed to alg none is not redirected back for", async ({
			op,
			configureClient,
		}) => {
			const { client, postLogoutRedirectUri, userinfoUrl } = await configureLogoutClient(op, configureClient);
			const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

			const unsignedIdToken = logout.changeIdTokenToAlgNone(tokens.idToken.value);
			await block("Redirect to end session endpoint & wait for response", async () => {
				const state = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
				const request = logout.createEndSessionEndpointRequest(
					unsignedIdToken,
					postLogoutRedirectUri,
					state,
					"OIDCRIL-2",
				);
				const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
				const errorPage = logout.expectInvalidIdTokenHintErrorPage("OIDCRIL-2");
				await logout.redirectToEndSessionEndpointExpectingNoRedirect(
					op,
					url,
					errorPage,
					"OP has incorrectly called the registered post_logout_redirect_uri even though an invalid id_token_hint was provided.",
				);
			});
		});

		// upstream: openid/OIDCCRpInitiatedLogoutNoIdTokenHint.java (OP-RpInitLogout-No-id_token_hint)
		test("oidcc-rp-initiated-logout-no-id-token-hint: without id_token_hint the OP does not redirect to the post_logout_redirect_uri", async ({
			op,
			configureClient,
		}) => {
			const { client, postLogoutRedirectUri, userinfoUrl } = await configureLogoutClient(op, configureClient);
			const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

			await block("Redirect to end session endpoint & wait for response", async () => {
				const state = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
				const request = logout.createEndSessionEndpointRequest(
					tokens.idToken.value,
					postLogoutRedirectUri,
					state,
					"OIDCRIL-2",
				);
				logout.removeIdTokenHintFromEndSessionEndpointRequest(request);
				const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
				const errorPage = logout.expectIdTokenHintRequiredErrorPage("OIDCRIL-2");
				await logout.redirectToEndSessionEndpointExpectingNoRedirect(
					op,
					url,
					errorPage,
					"OP has incorrectly called the registered post_logout_redirect_uri even though no id_token_hint was provided.",
				);
			});
		});

		// upstream: openid/OIDCCRpInitiatedLogoutBadLogoutRedirectUri.java (OP-RpInitLogout-Bad_redirect_uri)
		test("oidcc-rp-initiated-logout-bad-post-logout-redirect-uri: an unregistered post_logout_redirect_uri is not redirected to", async ({
			op,
			configureClient,
		}) => {
			const { client, postLogoutRedirectUri, userinfoUrl } = await configureLogoutClient(op, configureClient);
			const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

			await block("Redirect to end session endpoint & wait for response", async () => {
				const state = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
				const request = logout.createEndSessionEndpointRequest(
					tokens.idToken.value,
					postLogoutRedirectUri,
					state,
					"OIDCRIL-2",
				);
				logout.addBadPostLogoutRedirectUriToEndSessionEndpointRequest(request, op.baseUrl);
				const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
				const errorPage = logout.expectPostLogoutRedirectUriNotRegisteredErrorPage("OIDCRIL-2");
				await logout.redirectToEndSessionEndpointExpectingNoRedirect(
					op,
					url,
					errorPage,
					"OP has incorrectly called the registered post_logout_redirect_uri even though a different uri was requested.",
				);
			});
		});

		// upstream: openid/OIDCCRpInitiatedLogoutQueryAddedToLogoutRedirectUri.java (OP-RpInitLogout-Unregistered_post_logout_redirect_uri)
		test("oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri: a post_logout_redirect_uri with an added query is not redirected to", async ({
			op,
			configureClient,
		}) => {
			const { client, postLogoutRedirectUri, userinfoUrl } = await configureLogoutClient(op, configureClient);
			const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

			await block("Redirect to end session endpoint & wait for response", async () => {
				const state = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
				const request = logout.createEndSessionEndpointRequest(
					tokens.idToken.value,
					postLogoutRedirectUri,
					state,
					"OIDCRIL-2",
				);
				logout.addPostLogoutRedirectUriWithQueryAddedToEndSessionEndpointRequest(request);
				const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
				const errorPage = logout.expectPostLogoutRedirectUriNotRegisteredErrorPage("OIDCRIL-2");
				await logout.redirectToEndSessionEndpointExpectingNoRedirect(
					op,
					url,
					errorPage,
					"OP has incorrectly called the registered post_logout_redirect_uri even though a different uri was requested.",
				);
			});
		});

		// upstream: openid/OIDCCRpInitiatedLogoutNoParams.java (OP-RpInitLogout-No-params)
		test("oidcc-rp-initiated-logout-no-params: a logout request without parameters logs the user out and shows a logged out page", async ({
			op,
			configureClient,
		}) => {
			const { client, postLogoutRedirectUri, userinfoUrl } = await configureLogoutClient(op, configureClient);
			const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

			await block("Redirect to end session endpoint & wait for response", async () => {
				const state = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
				const request = logout.createEndSessionEndpointRequest(
					tokens.idToken.value,
					postLogoutRedirectUri,
					state,
					"OIDCRIL-2",
				);
				logout.removeAllParametersFromEndSessionEndpointRequest(request);
				const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
				const loggedOutPage = logout.expectSuccessfulLogoutPage("OIDCRIL-2");
				await logout.redirectToEndSessionEndpointExpectingNoRedirect(
					op,
					url,
					loggedOutPage,
					"OP has incorrectly called the registered post_logout_redirect_uri when it wasn't in the request.",
				);
			});
		});

		// upstream: openid/OIDCCRpInitiatedLogoutNoPostLogoutRedirectUri.java (OP-RpInitLogout-No-post_logout_redirect_uri)
		test("oidcc-rp-initiated-logout-no-post-logout-redirect-uri: without post_logout_redirect_uri the OP logs the user out and shows a logged out page", async ({
			op,
			configureClient,
		}) => {
			const { client, postLogoutRedirectUri, userinfoUrl } = await configureLogoutClient(op, configureClient);
			const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

			await block("Redirect to end session endpoint & wait for response", async () => {
				const state = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
				const request = logout.createEndSessionEndpointRequest(
					tokens.idToken.value,
					postLogoutRedirectUri,
					state,
					"OIDCRIL-2",
				);
				logout.removePostLogoutRedirectUriFromEndSessionEndpointRequest(request);
				const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
				const loggedOutPage = logout.expectSuccessfulLogoutPage("OIDCRIL-2");
				await logout.redirectToEndSessionEndpointExpectingNoRedirect(
					op,
					url,
					loggedOutPage,
					"OP has incorrectly called the registered post_logout_redirect_uri when it wasn't in the request.",
				);
			});
		});

		// upstream: openid/OIDCCRpInitiatedLogoutOnlyState.java (OP-RpInitLogout-Only-state)
		test("oidcc-rp-initiated-logout-only-state: with only a state the OP logs the user out and shows a logged out page", async ({
			op,
			configureClient,
		}) => {
			const { client, postLogoutRedirectUri, userinfoUrl } = await configureLogoutClient(op, configureClient);
			const { tokens } = await logout.performAuthorizationFlow(op, client, userinfoUrl);

			await block("Redirect to end session endpoint & wait for response", async () => {
				const state = logout.createRandomEndSessionState("OIDCRIL-2", "RFC6749A-A.5");
				const request = logout.createEndSessionEndpointRequest(
					tokens.idToken.value,
					postLogoutRedirectUri,
					state,
					"OIDCRIL-2",
				);
				logout.removeIdTokenHintFromEndSessionEndpointRequest(request);
				logout.removePostLogoutRedirectUriFromEndSessionEndpointRequest(request);
				const url = logout.buildRedirectToEndSessionEndpoint(op.metadata, request, "OIDCRIL-2");
				const loggedOutPage = logout.expectSuccessfulLogoutPage("OIDCRIL-2");
				await logout.redirectToEndSessionEndpointExpectingNoRedirect(
					op,
					url,
					loggedOutPage,
					"OP has incorrectly called the registered post_logout_redirect_uri when it wasn't in the request.",
				);
			});
		});
	});
});

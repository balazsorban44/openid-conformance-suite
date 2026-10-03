/**
 * OpenID Connect Core: Back Channel Logout RP Certification Profile, RP tests (upstream
 * openid/client/logout/plan/OIDCCClientBackChannelLogoutRPBasicTestPlan.java).
 *
 * The plan fixes response_type=code; the user selects client_auth_type, response_mode, request_type and
 * client_registration (CONFORMANCE_VARIANT or the CI project).
 *
 * The RP logs in, then sends its user agent to the end_session_endpoint (RP-Initiated Logout). The OP creates a
 * logout_token (each module breaks it in one way), redirects to the post_logout_redirect_uri and posts the
 * logout_token to the RP's backchannel_logout_uri: the RP must answer 200 for a valid logout_token, 400 otherwise
 * (OIDCBCL-2.8), with Cache-Control: no-store.
 *
 *   CONFORMANCE_PROJECT=rp-backchannel-logout pnpm test tests/rp/backchannel-logout.spec.ts
 */
import * as logout from "../../src/rp/logout.ts";
import type { RpClient } from "../../src/rp/registration.ts";
import { soft } from "../../src/suite/conditions.ts";
import { test } from "../fixtures.ts";

test.describe("oidcc-client-back-channel-logout-rp-basic", () => {
	test.use({
		plan: { name: "oidcc-client-back-channel-logout-rp-basic", variant: { response_type: "code" } },
	});

	// upstream: openid/client/logout/OIDCCClientTestBackChannelLogout.java (rp-backchannel-rpinitlogout)
	test("oidcc-client-test-rp-backchannel-rpinitlogout: the RP accepts a valid logout_token at its backchannel_logout_uri", async ({
		rp,
	}) => {
		const op = await rp.start(
			logout.logoutTestOptions({
				channels: "back",
				checkBackChannelLogoutResponse: (res) =>
					soft(() => logout.ensureBackChannelLogoutUriResponseStatusCodeIs200(res, "OIDCBCL-2.8")),
			}),
		);
		const client = rp.driveClient();
		await op.clientRegistered();
		// the RP logs in (token and userinfo requests are not required)
		await op.expect("authorization");
		// RP-initiated logout; the OP posts the logout_token to the backchannel_logout_uri before it redirects
		await op.expect("end_session");
		await client;
	});

	// upstream: openid/client/logout/OIDCCClientTestBackChannelLogoutAlgNone.java (rp-backchannel-rpinitlogout-lt-alg-none)
	test("oidcc-client-test-rp-backchannel-rpinitlogout-alg-none: the RP rejects an unsigned (alg none) logout_token", async ({
		rp,
	}) => {
		const op = await rp.start(
			logout.logoutTestOptions({
				channels: "back",
				signLogoutToken: (claims) => logout.oidccSignLogoutTokenWithAlgNone(claims),
				checkBackChannelLogoutResponse: (res) =>
					soft(() => logout.ensureBackChannelLogoutUriResponseStatusCodeIs400(res, "OIDCBCL-2.8")),
			}),
		);
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("end_session");
		await client;
	});

	// upstream: openid/client/logout/OIDCCClientTestBackChannelLogoutNoEvent.java (rp-backchannel-rpinitlogout-lt-no-event)
	test("oidcc-client-test-rp-backchannel-rpinitlogout-no-event: the RP rejects a logout_token without an events claim", async ({
		rp,
	}) => {
		const op = await rp.start(
			logout.logoutTestOptions({
				channels: "back",
				logoutTokenClaims: (claims) => logout.removeEventsClaimFromLogoutToken(claims, "OIDCBCL-2.4"),
				checkBackChannelLogoutResponse: (res) =>
					soft(() => logout.ensureBackChannelLogoutUriResponseStatusCodeIs400(res, "OIDCBCL-2.8")),
			}),
		);
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("end_session");
		await client;
	});

	// upstream: openid/client/logout/OIDCCClientTestBackChannelLogoutWithNonce.java (rp-backchannel-rpinitlogout-lt-with-nonce)
	test("oidcc-client-test-rp-backchannel-rpinitlogout-with-nonce: the RP rejects a logout_token with a nonce claim", async ({
		rp,
	}) => {
		const op = await rp.start(
			logout.logoutTestOptions({
				channels: "back",
				logoutTokenClaims: (claims) => logout.addNonceToLogoutToken(claims, "OIDCBCL-2.4"),
				checkBackChannelLogoutResponse: (res) =>
					soft(() => logout.ensureBackChannelLogoutUriResponseStatusCodeIs400(res, "OIDCBCL-2.8")),
			}),
		);
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("end_session");
		await client;
	});

	// upstream: openid/client/logout/OIDCCClientTestBackChannelLogoutWrongAlg.java (rp-backchannel-rpinitlogout-lt-wrong-alg)
	test("oidcc-client-test-rp-backchannel-rpinitlogout-wrong-alg: the RP rejects a logout_token signed with another algorithm than its id_tokens", async ({
		rp,
	}) => {
		const op = await rp.start(
			logout.logoutTestOptions({
				channels: "back",
				signLogoutToken: (claims, { keys, client, signingAlg }) =>
					logout.oidccSignLogoutTokenWithWrongAlgorithm(
						claims,
						keys.jwks,
						client as RpClient,
						signingAlg,
						"OIDCBCL-2.4",
					),
				checkBackChannelLogoutResponse: (res) =>
					soft(() => logout.ensureBackChannelLogoutUriResponseStatusCodeIs400(res, "OIDCBCL-2.8")),
			}),
		);
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("end_session");
		await client;
	});

	// upstream: openid/client/logout/OIDCCClientTestBackChannelLogoutWrongAud.java (rp-backchannel-rpinitlogout-lt-wrong-aud)
	test("oidcc-client-test-rp-backchannel-rpinitlogout-wrong-aud: the RP rejects a logout_token whose aud is not its client_id", async ({
		rp,
	}) => {
		const op = await rp.start(
			logout.logoutTestOptions({
				channels: "back",
				logoutTokenClaims: (claims) => logout.addInvalidAudValueToLogoutToken(claims, "OIDCBCL-2.4"),
				checkBackChannelLogoutResponse: (res) =>
					soft(() => logout.ensureBackChannelLogoutUriResponseStatusCodeIs400(res, "OIDCBCL-2.8")),
			}),
		);
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("end_session");
		await client;
	});

	// upstream: openid/client/logout/OIDCCClientTestBackChannelLogoutWrongEvent.java (rp-backchannel-rpinitlogout-lt-wrong-event)
	test("oidcc-client-test-rp-backchannel-rpinitlogout-wrong-event: the RP rejects a logout_token without the back-channel logout event", async ({
		rp,
	}) => {
		const op = await rp.start(
			logout.logoutTestOptions({
				channels: "back",
				logoutTokenClaims: (claims) => logout.addInvalidEventsClaimToLogoutToken(claims, "OIDCBCL-2.4"),
				checkBackChannelLogoutResponse: (res) =>
					soft(() => logout.ensureBackChannelLogoutUriResponseStatusCodeIs400(res, "OIDCBCL-2.8")),
			}),
		);
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("end_session");
		await client;
	});

	// upstream: openid/client/logout/OIDCCClientTestBackChannelLogoutWrongIssuer.java (rp-backchannel-rpinitlogout-lt-wrong-issuer)
	test("oidcc-client-test-rp-backchannel-rpinitlogout-wrong-iss: the RP rejects a logout_token whose iss is not the issuer", async ({
		rp,
	}) => {
		const op = await rp.start(
			logout.logoutTestOptions({
				channels: "back",
				logoutTokenClaims: (claims) => logout.addInvalidIssValueToLogoutToken(claims, "OIDCBCL-2.4"),
				checkBackChannelLogoutResponse: (res) =>
					soft(() => logout.ensureBackChannelLogoutUriResponseStatusCodeIs400(res, "OIDCBCL-2.8")),
			}),
		);
		const client = rp.driveClient();
		await op.clientRegistered();
		await op.expect("authorization");
		await op.expect("end_session");
		await client;
	});
});

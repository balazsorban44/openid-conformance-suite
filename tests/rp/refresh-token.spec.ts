/**
 * OpenID Connect Core Client Refresh Token Profile, RP tests (upstream
 * openid/client/OIDCCClientRefreshTokenProfileTestPlan.java; not part of the certification program).
 *
 * The plan leaves every variant parameter to the user (CONFORMANCE_VARIANT or the CI project). The emulated OP
 * announces the refresh_token grant and issues a refresh token with the code; the RP under test must use it and
 * (in the positive test) call userinfo with the refreshed access token, or (negative tests) reject the refresh
 * response and stop.
 *
 *   CONFORMANCE_PROJECT=rp-refresh-token pnpm test tests/rp/refresh-token.spec.ts
 */
import * as discovery from "../../src/rp/discovery.ts";
import * as idToken from "../../src/rp/id-token.ts";
import type { EmulatedOpOptions, RefreshOptions } from "../../src/rp/op.ts";
import { test, variantNotApplicable } from "../fixtures.ts";

/** The emulated OP of the refresh token modules (upstream AbstractOIDCCClientTestRefreshToken) */
function refreshTokenOpOptions(refresh: RefreshOptions = {}): EmulatedOpOptions {
	return { serverConfiguration: discovery.oidccGenerateServerConfigurationWithRefreshTokenGrantType, refresh };
}

test.describe("oidcc-client-refreshtoken-test-plan", () => {
	const plan = { name: "oidcc-client-refreshtoken-test-plan", variant: {} };
	test.use({ plan });

	// upstream @VariantNotApplicable(parameter = ResponseType.class, values = { "id_token", "id_token token" }): no
	// token endpoint, no refresh token
	if (!variantNotApplicable(plan, { response_type: ["id_token", "id_token token"] })) {
		// upstream: openid/client/OIDCCClientTestRefreshToken.java
		test("oidcc-client-test-refresh-token: the RP refreshes its access token and calls userinfo with the new one", async ({
			rp,
		}) => {
			const op = await rp.start(refreshTokenOpOptions());
			const client = rp.driveClient();
			await op.clientRegistered();
			await op.expect("authorization");
			await op.expect("token");
			// the refresh request; a userinfo request the RP made before it does not complete the test
			await op.expect("token");
			// upstream finishes the test after the userinfo request with the refreshed access token
			await op.expect("userinfo");
			await client;
		});

		// upstream: openid/client/OIDCCClientTestRefreshTokenInvalidIssuer.java
		test("oidcc-client-test-refresh-token-invalid-issuer: the RP rejects a refresh response whose id_token has another iss", async ({
			rp,
		}) => {
			const op = await rp.start(
				refreshTokenOpOptions({
					customIdTokenClaims: (claims) => idToken.addInvalidIssValueToIdToken(claims, "OIDCC-12.2"),
					userinfoAfterRefreshFails:
						"The client should not send a userinfo request after receiving an invalid refresh response. Clients are expected to send a token request to obtain a refresh token and then use that refresh token to send a refresh request and detect that the id_token in the refresh response contains an invalid iss value.",
				}),
			);
			const client = rp.driveClient();
			await op.clientRegistered();
			await op.expect("authorization");
			await op.expect("token");
			await op.expect("token");
			// the RP must reject the id_token and stop: no userinfo request within waitTimeoutSeconds
			await op.waitFor("userinfo", rp.waitTimeoutSeconds);
			await client;
		});

		// upstream: openid/client/OIDCCClientTestRefreshTokenInvalidSub.java
		test("oidcc-client-test-refresh-token-invalid-sub: the RP rejects a refresh response whose id_token has another sub", async ({
			rp,
		}) => {
			const op = await rp.start(
				refreshTokenOpOptions({
					customIdTokenClaims: (claims) => idToken.addInvalidSubValueToIdToken(claims, "OIDCC-12.2"),
					userinfoAfterRefreshFails:
						"The client should not send a userinfo request after receiving an invalid refresh response. Clients are expected to send a token request to obtain a refresh token and then use that refresh token to send a refresh request and detect that the id_token in the refresh response contains an invalid sub value.",
				}),
			);
			const client = rp.driveClient();
			await op.clientRegistered();
			await op.expect("authorization");
			await op.expect("token");
			await op.expect("token");
			// the RP must reject the id_token and stop: no userinfo request within waitTimeoutSeconds
			await op.waitFor("userinfo", rp.waitTimeoutSeconds);
			await client;
		});
	}
});

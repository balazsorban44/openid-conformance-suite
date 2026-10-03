/**
 * The bodies of RP tests whose upstream module is part of more than one plan. Each plan's spec registers them
 * with the module's title and `// upstream:` comment:
 *
 *   // upstream: openid/client/OIDCCClientTestIdTokenSigAlgNone.java (rp-id_token-sig-none)
 *   test("oidcc-client-test-idtoken-sig-none: ...", shared.idTokenSigNone);
 */
import * as authz from "../../src/rp/authorization.ts";
import * as idToken from "../../src/rp/id-token.ts";
import * as registration from "../../src/rp/registration.ts";
import type { Rp } from "../../src/rp/rp.ts";

/**
 * oidcc-client-test-idtoken-sig-none: the RP accepts an unsigned id_token from the token endpoint, or stops.
 *
 * The port of openid/client/OIDCCClientTestIdTokenSigAlgNone.java (the specs carry the upstream reference).
 */
export async function idTokenSigNone({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		registrationSteps: (c) => {
			registration.setClientIdTokenSignedResponseAlgToNone(c);
			registration.setClientGrantTypesToAuthorizationCodeOnly(c);
		},
		signingAlg: () => idToken.setServerSigningAlgToNone(),
		checkResponseType: (params) => authz.ensureResponseTypeIs(params, "code", "OIDCR-2"),
		signIdToken: (claims) => idToken.signIdTokenWithAlgNone(claims),
	});
	const client = rp.driveClient();
	await op.clientRegistered();
	await op.expect("authorization");
	await op.expect("token");
	// clients are not required to support unsigned id_tokens: the RP either calls userinfo or stops
	const info = await op.waitFor("userinfo", rp.waitTimeoutSeconds);
	if (info == null) {
		rp.skipTest(
			"Client did not send a userinfo request after receiving an unsigned id_token. As clients are not required to support unsigned (alg: none) id_tokens this is okay.",
		);
	}
	await client;
}

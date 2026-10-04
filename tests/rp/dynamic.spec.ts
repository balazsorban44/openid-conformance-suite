/**
 * OpenID Connect Core: Dynamic Certification Profile, RP tests (upstream openid/client/OIDCClientDynamicTestPlan.java,
 * the tests of the profile document's table, in its order).
 *
 * The plan fixes response_type=code, client_registration=dynamic_client (dynamic registration is required) and
 * request_type=request_uri (two tests need it): every authorization request carries a request object by reference,
 * which the emulated OP fetches and checks. The user selects client_auth_type and response_mode.
 *
 * Every test starts the emulated OP (rp.start: what this module's OP does differently), makes the RP under test
 * log in against it (rp.driveClient), then follows the requests the RP sends. The modules the config plan has too
 * (discovery, key rotation, alg none) have their bodies in ./shared.ts.
 *
 *   CONFORMANCE_PROJECT=rp-dynamic pnpm test tests/rp/dynamic.spec.ts
 */
import * as discovery from "../../src/rp/discovery.ts";
import { failTest } from "../../src/rp/op.ts";
import * as requestObject from "../../src/rp/request-object.ts";
import * as userinfo from "../../src/rp/userinfo.ts";
import { selectedVariant, test, variantNotApplicable } from "../fixtures.ts";
import * as shared from "./shared.ts";

test.describe("oidcc-client-dynamic-certification-test-plan", () => {
	const plan = {
		name: "oidcc-client-dynamic-certification-test-plan",
		variant: { response_type: "code", client_registration: "dynamic_client", request_type: "request_uri" },
	};
	test.use({ plan });

	// upstream: openid/client/config/OIDCCClientTestDiscoveryWebfingerAcct.java (rp-discovery-webfinger-acct)
	test("oidcc-client-test-discovery-webfinger-acct: the RP finds the issuer with WebFinger for an acct: identifier and fetches its configuration", async ({
		rp,
	}) => {
		const op = await rp.start({
			// the issuer gets a random suffix: only WebFinger tells the RP where the configuration is
			serverConfiguration: (baseUrl) => {
				const server = discovery.oidccGenerateServerConfiguration(baseUrl);
				discovery.addRandomSuffixToIssuerInServerConfiguration(server);
				return server;
			},
			// acct:<alias>.<test name>@<host>
			validateWebfingerResource: (resourcePrefix) => {
				if (resourcePrefix !== "acct") {
					failTest("This test expects a webfinger request using acct syntax");
				}
			},
		});
		const client = rp.driveClient();
		// upstream finishes the test after the discovery request
		await op.expect("discovery");
		await client;
	});

	// upstream: openid/client/config/OIDCCClientTestDiscoveryWebfingerURL.java (rp-discovery-webfinger-url)
	test("oidcc-client-test-discovery-webfinger-url: the RP finds the issuer with WebFinger for a URL identifier and fetches its configuration", async ({
		rp,
	}) => {
		const op = await rp.start({
			// the issuer gets a random suffix: only WebFinger tells the RP where the configuration is
			serverConfiguration: (baseUrl) => {
				const server = discovery.oidccGenerateServerConfiguration(baseUrl);
				discovery.addRandomSuffixToIssuerInServerConfiguration(server);
				return server;
			},
			// https://<host>/<alias>/<test name>
			validateWebfingerResource: (resourcePrefix) => {
				if (resourcePrefix !== "https") {
					failTest(
						"This test expects a webfinger request using URL syntax " +
							"(e.g https://example.com/test-alias/" +
							rp.testName +
							")",
					);
				}
			},
		});
		const client = rp.driveClient();
		// upstream finishes the test after the discovery request
		await op.expect("discovery");
		await client;
	});

	// upstream: openid/client/config/OIDCCClientTestDiscoveryOpenIDConfiguration.java (rp-discovery-openid-configuration)
	test(
		"oidcc-client-test-discovery-openid-config: the RP fetches the OP's configuration from .well-known/openid-configuration",
		shared.discoveryOpenIdConfig,
	);

	// upstream: openid/client/config/OIDCCClientTestDiscoveryJwksUriKeys.java (rp-discovery-jwks_uri-keys)
	test(
		"oidcc-client-test-discovery-jwks-uri-keys: the RP fetches the keys from the jwks_uri of the OP's configuration",
		shared.discoveryJwksUriKeys,
	);

	// upstream: openid/client/config/OIDCCClientTestDiscoveryIssuerMismatch.java (rp-discovery-issuer-not-matching-config)
	test(
		"oidcc-client-test-discovery-issuer-mismatch: the RP stops when the configuration's issuer is not the one WebFinger returned",
		shared.discoveryIssuerMismatch,
	);

	// the plan has this module for dynamic clients only
	if (!variantNotApplicable(plan, { client_registration: ["static_client"] })) {
		// upstream: openid/client/config/OIDCCClientTestDynamicRegistration.java (rp-registration-dynamic)
		test("oidcc-client-test-dynamic-registration: the RP registers itself at the registration endpoint", async ({
			rp,
		}) => {
			const op = await rp.start();
			const client = rp.driveClient();
			// upstream finishes the test after the registration request
			await op.expect("registration");
			await client;
		});
	}

	// the plan has these modules for request_type=request_uri only
	if (selectedVariant(plan).request_type === "request_uri") {
		// upstream: openid/client/OIDCCClientTestRequestUriSignedWithRS256.java (rp-request_uri-sig)
		test("oidcc-client-test-request-uri-signed-rs256: the RP passes an RS256 signed request object by reference and completes the flow", async ({
			rp,
		}) => {
			const op = await rp.start({
				checkClientMetadata: (c) => requestObject.ensureRequestObjectSigningAlgIsRS256InClientMetadata(c),
				checkRequestObject: (ro) => requestObject.ensureRequestObjectWasSignedWithRS256(ro),
			});
			const client = rp.driveClient();
			await op.clientRegistered();
			// the OP fetches the request object from the request_uri and checks it
			await op.expect("authorization");
			await op.expect("token");
			await op.expect("userinfo");
			await client;
		});

		// upstream: openid/client/OIDCCClientTestRequestUriSignedWithNone.java (rp-request_uri-unsigned)
		test("oidcc-client-test-request-uri-signed-none: the RP passes an unsigned request object by reference and completes the flow", async ({
			rp,
		}) => {
			const op = await rp.start({
				checkClientMetadata: (c) => requestObject.ensureRequestObjectSigningAlgIsNoneInClientMetadata(c),
				checkRequestObject: (ro) => requestObject.ensureRequestObjectWasSignedWithNone(ro),
			});
			const client = rp.driveClient();
			await op.clientRegistered();
			// the OP fetches the request object from the request_uri (which must be https as it is unsigned)
			await op.expect("authorization");
			await op.expect("token");
			await op.expect("userinfo");
			await client;
		});
	}

	// the plan has this module for the code flow only
	if (selectedVariant(plan).response_type === "code") {
		// upstream: openid/client/OIDCCClientTestIdTokenSigAlgNone.java (rp-id_token-sig-none)
		test(
			"oidcc-client-test-idtoken-sig-none: the RP accepts an unsigned id_token from the token endpoint, or stops",
			shared.idTokenSigNone,
		);
	}

	// upstream: openid/client/config/OIDCCClientTestSigningKeyRotationJustBeforeSigning.java (rp-key-rotation-op-sign-key-native)
	test(
		"oidcc-client-test-signing-key-rotation-just-before-signing: the RP fetches the OP's keys again to verify an id_token signed with a new key",
		shared.signingKeyRotationJustBeforeSigning,
	);

	// upstream: openid/client/config/OIDCCClientTestSigningKeyRotation.java (rp-key-rotation-op-sign-key)
	test(
		"oidcc-client-test-signing-key-rotation: the RP logs in twice and fetches the OP's keys again after they were rotated",
		shared.signingKeyRotation,
	);

	// upstream @VariantNotApplicable(parameter = ResponseType.class, values = { "id_token" }): no access token, no userinfo
	if (!variantNotApplicable(plan, { response_type: ["id_token"] })) {
		// upstream: openid/client/OIDCCClientTestSignedUserinfo.java (rp-userinfo-sig)
		test("oidcc-client-test-userinfo-signed: the RP accepts a userinfo response signed with RS256", async ({ rp }) => {
			const op = await rp.start({
				checkClientMetadata: (c) => userinfo.setUserinfoSignedResponseAlgToRS256(c),
			});
			const client = rp.driveClient();
			await op.clientRegistered();
			await op.expect("authorization");
			await op.expect("token");
			// the response is a JWT signed with the OP's key (with iss and aud)
			await op.expect("userinfo");
			await client;
		});
	}
});

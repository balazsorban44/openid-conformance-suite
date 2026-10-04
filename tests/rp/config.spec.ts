/**
 * OpenID Connect Core: Configuration Certification Profile, RP tests (upstream
 * openid/client/OIDCCClientConfigTestPlan.java, in the order of the old suite's list for the CNF profile).
 *
 * The plan fixes response_type=code (as the python suite did); the user selects client_auth_type, response_mode,
 * client_registration and request_type (CONFORMANCE_VARIANT or the CI project). Every module is in the dynamic plan
 * too (tests/rp/dynamic.spec.ts): the RP finds the OP's configuration and keys, rejects a configuration whose issuer
 * is wrong, and follows the OP's key rotation. The bodies are in ./shared.ts.
 *
 *   CONFORMANCE_PROJECT=rp-config pnpm test tests/rp/config.spec.ts
 */
import { selectedVariant, test } from "../fixtures.ts";
import * as shared from "./shared.ts";

test.describe("oidcc-client-config-certification-test-plan", () => {
	const plan = { name: "oidcc-client-config-certification-test-plan", variant: { response_type: "code" } };
	test.use({ plan });

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
});

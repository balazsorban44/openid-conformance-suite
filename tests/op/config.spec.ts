/**
 * OpenID Connect Core: Config Certification Profile, OP tests (upstream openid/OIDCCConfigTestPlan.java).
 *
 * The plan has one module, the discovery endpoint verification, run with discovery and a static client.
 *
 *   CONFORMANCE_PROJECT=op-config pnpm test tests/op/config.spec.ts
 */
import { test } from "../fixtures.ts";
import { oidccDiscoveryEndpointVerification } from "./shared.ts";

test.describe("oidcc-config-certification-test-plan", () => {
	test.use({
		plan: {
			name: "oidcc-config-certification-test-plan",
			variant: { server_metadata: "discovery", client_registration: "static_client" },
		},
	});

	// upstream: openid/OIDCCDiscoveryEndpointVerification.java (OP-Discovery-Config)
	test(
		"oidcc-discovery-endpoint-verification: the discovery document is served as JSON and has the metadata the specifications require",
		oidccDiscoveryEndpointVerification,
	);
});

/**
 * The CI matrix: every entry becomes a Playwright project and a GitHub Actions job. `plan` + `variant` select the
 * module instances (see VariantService.expandPlan), `config` is the test configuration file (which also names the
 * implementation under test to start).
 *
 * Mirrors upstream `.gitlab-ci/run-tests.sh` (makeOidccTest / makeClientTest / local provider runs).
 */
export interface ConformanceProject {
	name: string;
	plan: string;
	variant: string;
	config: string;
	/** Modules in the plan to skip in CI (known untestable in this setup), by testName */
	/** modules not run in this project: testName -> why (shown as the Playwright skip reason) */
	skipModules?: Record<string, string>;
}

export const projects: ConformanceProject[] = [
	// ---- OP plans against panva oidc-provider ----
	{
		name: "op-basic-static",
		plan: "oidcc-basic-certification-test-plan",
		variant: "[server_metadata=discovery][client_registration=static_client]",
		config: "configs/oidc-provider/oidcc-basic-static.json",
	},
	{
		name: "op-basic-dynamic",
		plan: "oidcc-basic-certification-test-plan",
		variant: "[server_metadata=discovery][client_registration=dynamic_client]",
		config: "configs/oidc-provider/oidcc-basic-dynamic.json",
	},
	{
		name: "op-config",
		plan: "oidcc-config-certification-test-plan",
		variant: "",
		config: "configs/oidc-provider/oidcc-config.json",
	},
	{
		name: "op-dynamic",
		plan: "oidcc-dynamic-certification-test-plan",
		variant: "[response_type=code][client_auth_type=client_secret_basic][response_mode=default]",
		config: "configs/oidc-provider/oidcc-dynamic.json",
	},
	{
		name: "op-rp-initiated-logout",
		plan: "oidcc-rp-initiated-logout-certification-test-plan",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][server_metadata=discovery][client_registration=dynamic_client]",
		config: "configs/oidc-provider/oidcc-rp-initiated-logout.json",
	},
	{
		name: "op-backchannel-logout",
		plan: "oidcc-backchannel-rp-initiated-logout-certification-test-plan",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][server_metadata=discovery][client_registration=dynamic_client]",
		config: "configs/oidc-provider/oidcc-backchannel-logout.json",
	},
	{
		name: "op-frontchannel-logout",
		plan: "oidcc-frontchannel-rp-initiated-logout-certification-test-plan",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][server_metadata=discovery][client_registration=dynamic_client]",
		config: "configs/oidc-provider/oidcc-frontchannel-logout.json",
	},
	{
		name: "op-session-management",
		plan: "oidcc-session-management-certification-test-plan",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][server_metadata=discovery][client_registration=dynamic_client]",
		config: "configs/oidc-provider/oidcc-session-management.json",
	},
	{
		name: "op-3rdparty-init-login",
		plan: "oidcc-3rdparty-init-login-certification-test-plan",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][server_metadata=discovery][client_registration=dynamic_client]",
		config: "configs/oidc-provider/oidcc-3rdparty-init-login.json",
	},
	// ---- RP plans against the openid-client based RP ----
	{
		name: "rp-basic",
		plan: "oidcc-client-basic-certification-test-plan",
		variant: "[client_registration=dynamic_client][request_type=plain_http_request]",
		config: "configs/openid-client-rp/oidcc-client-basic.json",
	},
	{
		name: "rp-dynamic",
		plan: "oidcc-client-dynamic-certification-test-plan",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][request_type=plain_http_request][client_registration=dynamic_client]",
		config: "configs/openid-client-rp/oidcc-client-dynamic.json",
	},
	{
		name: "rp-rp-initiated-logout",
		plan: "oidcc-client-rp-initiated-logout-rp-basic",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][request_type=plain_http_request][client_registration=dynamic_client]",
		config: "configs/openid-client-rp/oidcc-client-rp-initiated-logout.json",
	},
	{
		name: "rp-backchannel-logout",
		plan: "oidcc-client-back-channel-logout-rp-basic",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][request_type=plain_http_request][client_registration=dynamic_client]",
		config: "configs/openid-client-rp/oidcc-client-back-channel-logout.json",
	},
	{
		name: "rp-frontchannel-logout",
		plan: "oidcc-client-front-channel-logout-rp-basic",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][request_type=plain_http_request][client_registration=dynamic_client]",
		config: "configs/openid-client-rp/oidcc-client-front-channel-logout.json",
	},
	{
		name: "rp-session-management",
		plan: "oidcc-client-rp-session-management-rp-basic",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][request_type=plain_http_request][client_registration=dynamic_client]",
		config: "configs/openid-client-rp/oidcc-client-session-management.json",
	},
	{
		name: "rp-3rdparty-init-login",
		plan: "oidcc-client-test-3rd-party-init-login-test-plan",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][request_type=plain_http_request][client_registration=dynamic_client]",
		config: "configs/openid-client-rp/oidcc-client-3rd-party-init-login.json",
	},
	// ---- suite vs suite: our OP tests against our own emulated OP (RP test module as the OP) ----
	{
		name: "suite-vs-suite",
		plan: "oidcc-basic-certification-test-plan",
		variant: "[server_metadata=discovery][client_registration=dynamic_client]",
		config: "configs/suite-vs-suite/oidcc-basic.json",
		// the emulated OP is upstream's single-flow RP test module (oidcc-client-test); what it cannot do is skipped
		// here, what it does differently is in configs/expected-failures/suite-vs-suite.json
		skipModules: {
			"oidcc-prompt-login": "the emulated OP serves one authorization flow; a second token request fails",
			"oidcc-prompt-none-logged-in": "the emulated OP serves one authorization flow; a second token request fails",
			"oidcc-max-age-1": "the emulated OP serves one authorization flow; a second token request fails",
			"oidcc-max-age-10000": "the emulated OP serves one authorization flow; a second token request fails",
			"oidcc-id-token-hint": "the emulated OP serves one authorization flow; a second token request fails",
			"oidcc-refresh-token": "the emulated OP knows one registered client; this module registers a second one",
			"oidcc-response-type-missing":
				"the emulated OP answers an invalid request with a 400 page instead of an error redirect",
			"oidcc-ensure-registered-redirect-uri":
				"the emulated OP answers an invalid request with a 400 page instead of an error page",
			"oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported":
				"the emulated OP (request_type=plain_http_request) answers request objects with a 400 page",
			"oidcc-ensure-request-object-with-redirect-uri":
				"the emulated OP (request_type=plain_http_request) answers request objects with a 400 page",
		},
	},
];

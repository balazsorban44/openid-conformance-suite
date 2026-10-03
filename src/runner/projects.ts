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
	skipModules?: string[];
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
		config: "configs/openid-client-rp/oidcc-client-backchannel-logout.json",
	},
	{
		name: "rp-frontchannel-logout",
		plan: "oidcc-client-front-channel-logout-rp-basic",
		variant:
			"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][request_type=plain_http_request][client_registration=dynamic_client]",
		config: "configs/openid-client-rp/oidcc-client-frontchannel-logout.json",
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
		config: "configs/openid-client-rp/oidcc-client-3rdparty-init-login.json",
	},
	// ---- suite vs suite: our OP tests against our own emulated OP (RP test module as the OP) ----
	{
		name: "suite-vs-suite",
		plan: "oidcc-basic-certification-test-plan",
		variant: "[server_metadata=discovery][client_registration=dynamic_client]",
		config: "configs/suite-vs-suite/oidcc-basic.json",
	},
];

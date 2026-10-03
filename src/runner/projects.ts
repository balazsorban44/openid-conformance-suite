/**
 * The CI matrix: every entry becomes a Playwright project and a GitHub Actions job (.github/workflows/ci.yml reads
 * the names from `openid-conformance projects --json`). `plan` + `variant` select the module instances (see
 * `expandPlan` in src/framework/VariantService.ts), `config` is the test configuration file (which also names the
 * implementation under test to start).
 *
 * Mirrors upstream `.gitlab-ci/run-tests.sh` (makeOidccTest / makeClientTest / local provider runs).
 */
/**
 * Plans (partly) rewritten as explicit Playwright specs (tests/op/*.spec.ts, tests/rp/*.spec.ts): the spec file and
 * the modules it covers. tests/plan.spec.ts runs the rest of a plan's modules on the old framework, so a project
 * keeps running its whole plan while the rewrite progresses; when a plan is complete, its modules list is the whole
 * plan and plan.spec.ts no longer runs anything for it.
 */
export const portedPlans: Record<string, { spec: string; modules: string[] }> = {
	"oidcc-basic-certification-test-plan": {
		spec: "tests/op/basic.spec.ts",
		modules: [
			"oidcc-server",
			"oidcc-response-type-missing",
			"oidcc-idtoken-signature",
			"oidcc-codereuse",
			"oidcc-scope-address",
			"oidcc-scope-all",
			"oidcc-scope-email",
			"oidcc-scope-phone",
			"oidcc-scope-profile",
			"oidcc-claims-essential",
			"oidcc-claims-locales",
			"oidcc-userinfo-get",
			"oidcc-userinfo-post-body",
			"oidcc-userinfo-post-header",
			"oidcc-alternate-happy-flow",
			"oidcc-display-page",
			"oidcc-display-popup",
			"oidcc-ui-locales",
			"oidcc-login-hint",
			"oidcc-id-token-hint",
			"oidcc-prompt-login",
			"oidcc-prompt-none-logged-in",
			"oidcc-prompt-none-not-logged-in",
			"oidcc-max-age-1",
			"oidcc-max-age-10000",
			"oidcc-ensure-post-request-succeeds",
			"oidcc-ensure-registered-redirect-uri",
			"oidcc-ensure-request-object-with-redirect-uri",
			"oidcc-ensure-request-with-acr-values-succeeds",
			"oidcc-ensure-request-with-unknown-parameter-succeeds",
			"oidcc-ensure-request-with-valid-pkce-succeeds",
			"oidcc-ensure-request-without-nonce-succeeds-for-code-flow",
			"oidcc-refresh-token",
			"oidcc-codereuse-30seconds",
			"oidcc-server-client-secret-post",
			"oidcc-idtoken-unsigned",
			"oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported",
			"oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported",
		],
	},
	"oidcc-rp-initiated-logout-certification-test-plan": {
		spec: "tests/op/rp-initiated-logout.spec.ts",
		modules: [
			"oidcc-rp-initiated-logout-discovery-endpoint-verification",
			"oidcc-rp-initiated-logout",
			"oidcc-rp-initiated-logout-bad-post-logout-redirect-uri",
			"oidcc-rp-initiated-logout-modified-id-token-hint",
			"oidcc-rp-initiated-logout-no-id-token-hint",
			"oidcc-rp-initiated-logout-no-params",
			"oidcc-rp-initiated-logout-no-post-logout-redirect-uri",
			"oidcc-rp-initiated-logout-no-state",
			"oidcc-rp-initiated-logout-only-state",
			"oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri",
			"oidcc-rp-initiated-logout-bad-id-token-hint",
		],
	},
	"oidcc-backchannel-rp-initiated-logout-certification-test-plan": {
		spec: "tests/op/backchannel-logout.spec.ts",
		modules: ["oidcc-backchannel-logout-discovery-endpoint-verification", "oidcc-backchannel-rp-initiated-logout"],
	},
	"oidcc-frontchannel-rp-initiated-logout-certification-test-plan": {
		spec: "tests/op/frontchannel-logout.spec.ts",
		modules: ["oidcc-frontchannel-logout-discovery-endpoint-verification", "oidcc-frontchannel-rp-initiated-logout"],
	},
	"oidcc-session-management-certification-test-plan": {
		spec: "tests/op/session-management.spec.ts",
		modules: [
			"oidcc-session-management-discovery-endpoint-verification",
			"oidcc-session-management-rp-initiated-logout",
		],
	},
	"oidcc-3rdparty-init-login-certification-test-plan": {
		spec: "tests/op/3rdparty-init-login.spec.ts",
		modules: ["oidcc-3rd_party-init-login", "oidcc-3rd_party-init-login-nohttps"],
	},
	"oidcc-client-basic-certification-test-plan": {
		spec: "tests/rp/basic.spec.ts",
		modules: [
			"oidcc-client-test",
			"oidcc-client-test-invalid-iss",
			"oidcc-client-test-missing-sub",
			"oidcc-client-test-invalid-aud",
			"oidcc-client-test-missing-iat",
			"oidcc-client-test-kid-absent-single-jwks",
			"oidcc-client-test-kid-absent-multiple-jwks",
			"oidcc-client-test-idtoken-sig-rs256",
			"oidcc-client-test-idtoken-sig-none",
			"oidcc-client-test-invalid-sig-rs256",
			"oidcc-client-test-userinfo-invalid-sub",
			"oidcc-client-test-nonce-invalid",
			"oidcc-client-test-scope-userinfo-claims",
			"oidcc-client-test-client-secret-basic",
		],
	},
	"oidcc-client-dynamic-certification-test-plan": {
		spec: "tests/rp/dynamic.spec.ts",
		modules: [
			"oidcc-client-test-discovery-webfinger-acct",
			"oidcc-client-test-discovery-webfinger-url",
			"oidcc-client-test-discovery-openid-config",
			"oidcc-client-test-discovery-jwks-uri-keys",
			"oidcc-client-test-discovery-issuer-mismatch",
			"oidcc-client-test-dynamic-registration",
			"oidcc-client-test-request-uri-signed-rs256",
			"oidcc-client-test-request-uri-signed-none",
			"oidcc-client-test-idtoken-sig-none",
			"oidcc-client-test-signing-key-rotation-just-before-signing",
			"oidcc-client-test-signing-key-rotation",
			"oidcc-client-test-userinfo-signed",
		],
	},
	"oidcc-client-rp-initiated-logout-rp-basic": {
		spec: "tests/rp/rp-initiated-logout.spec.ts",
		modules: [
			"oidcc-client-test-rp-init-logout",
			"oidcc-client-test-rp-init-logout-other-state",
			"oidcc-client-test-rp-init-logout-no-state",
		],
	},
	"oidcc-client-back-channel-logout-rp-basic": {
		spec: "tests/rp/backchannel-logout.spec.ts",
		modules: [
			"oidcc-client-test-rp-backchannel-rpinitlogout",
			"oidcc-client-test-rp-backchannel-rpinitlogout-alg-none",
			"oidcc-client-test-rp-backchannel-rpinitlogout-no-event",
			"oidcc-client-test-rp-backchannel-rpinitlogout-with-nonce",
			"oidcc-client-test-rp-backchannel-rpinitlogout-wrong-alg",
			"oidcc-client-test-rp-backchannel-rpinitlogout-wrong-aud",
			"oidcc-client-test-rp-backchannel-rpinitlogout-wrong-event",
			"oidcc-client-test-rp-backchannel-rpinitlogout-wrong-iss",
		],
	},
	"oidcc-client-front-channel-logout-rp-basic": {
		spec: "tests/rp/frontchannel-logout.spec.ts",
		modules: ["oidcc-client-test-rp-frontchannel-rpinitlogout"],
	},
	"oidcc-client-rp-session-management-rp-basic": {
		spec: "tests/rp/session-management.spec.ts",
		modules: ["oidcc-client-test-session-management"],
	},
	"oidcc-client-test-3rd-party-init-login-test-plan": {
		spec: "tests/rp/3rdparty-init-login.spec.ts",
		modules: ["oidcc-client-test-3rd-party-init-login"],
	},
	"oidcc-config-certification-test-plan": {
		spec: "tests/op/config.spec.ts",
		modules: ["oidcc-discovery-endpoint-verification"],
	},
	"oidcc-dynamic-certification-test-plan": {
		spec: "tests/op/dynamic.spec.ts",
		modules: [
			"oidcc-discovery-endpoint-verification",
			"oidcc-server",
			"oidcc-ensure-client-assertion-with-iss-aud-succeeds",
			"oidcc-ensure-redirect-uri-in-authorization-request",
			"oidcc-ensure-request-object-with-redirect-uri",
			"oidcc-idtoken-rs256",
			"oidcc-idtoken-unsigned",
			"oidcc-redirect-uri-query-OK",
			"oidcc-redirect-uri-query-added",
			"oidcc-redirect-uri-query-mismatch",
			"oidcc-redirect-uri-regfrag",
			"oidcc-refresh-token",
			"oidcc-refresh-token-rp-key-rotation",
			"oidcc-registration-jwks-uri",
			"oidcc-registration-logo-uri",
			"oidcc-registration-policy-uri",
			"oidcc-registration-sector-bad",
			"oidcc-registration-sector-uri",
			"oidcc-registration-tos-uri",
			"oidcc-request-uri-signed-rs256",
			"oidcc-request-uri-unsigned",
			"oidcc-server-rotate-keys",
			"oidcc-userinfo-rs256",
		],
	},
};

export interface ConformanceProject {
	name: string;
	plan: string;
	variant: string;
	config: string;
	/**
	 * modules not run in this project: testName -> why (the Playwright skip reason; the `conformance` fixture of
	 * tests/fixtures.ts and tests/plan.spec.ts skip them)
	 */
	skipModules?: Record<string, string>;
}

const DISCOVERY_DYNAMIC = "[server_metadata=discovery][client_registration=dynamic_client]";
/** the variant the OP logout / session management / 3rd-party-initiated login plans run with */
const OP_CODE_BASIC =
	"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][server_metadata=discovery][client_registration=dynamic_client]";
/** the variant the RP dynamic / logout / session management / 3rd-party-initiated login plans run with */
const RP_CODE_BASIC =
	"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][request_type=plain_http_request][client_registration=dynamic_client]";

const INVALID_REQUEST_500 =
	"the emulated OP fails an invalid authorization request (as an RP test would) and answers with a 500 server_error";
const REQUEST_OBJECT_500 =
	"the emulated OP (request_type=plain_http_request) fails a request object (EnsureRequestDoesNotContainRequestObject) and answers with a 500 server_error";

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
		variant: DISCOVERY_DYNAMIC,
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
		variant: OP_CODE_BASIC,
		config: "configs/oidc-provider/oidcc-rp-initiated-logout.json",
	},
	{
		name: "op-backchannel-logout",
		plan: "oidcc-backchannel-rp-initiated-logout-certification-test-plan",
		variant: OP_CODE_BASIC,
		config: "configs/oidc-provider/oidcc-backchannel-logout.json",
	},
	{
		name: "op-frontchannel-logout",
		plan: "oidcc-frontchannel-rp-initiated-logout-certification-test-plan",
		variant: OP_CODE_BASIC,
		config: "configs/oidc-provider/oidcc-frontchannel-logout.json",
	},
	{
		name: "op-session-management",
		plan: "oidcc-session-management-certification-test-plan",
		variant: OP_CODE_BASIC,
		config: "configs/oidc-provider/oidcc-session-management.json",
	},
	{
		name: "op-3rdparty-init-login",
		plan: "oidcc-3rdparty-init-login-certification-test-plan",
		variant: OP_CODE_BASIC,
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
		variant: RP_CODE_BASIC,
		config: "configs/openid-client-rp/oidcc-client-dynamic.json",
	},
	{
		name: "rp-rp-initiated-logout",
		plan: "oidcc-client-rp-initiated-logout-rp-basic",
		variant: RP_CODE_BASIC,
		config: "configs/openid-client-rp/oidcc-client-rp-initiated-logout.json",
	},
	{
		name: "rp-backchannel-logout",
		plan: "oidcc-client-back-channel-logout-rp-basic",
		variant: RP_CODE_BASIC,
		config: "configs/openid-client-rp/oidcc-client-back-channel-logout.json",
	},
	{
		name: "rp-frontchannel-logout",
		plan: "oidcc-client-front-channel-logout-rp-basic",
		variant: RP_CODE_BASIC,
		config: "configs/openid-client-rp/oidcc-client-front-channel-logout.json",
	},
	{
		name: "rp-session-management",
		plan: "oidcc-client-rp-session-management-rp-basic",
		variant: RP_CODE_BASIC,
		config: "configs/openid-client-rp/oidcc-client-session-management.json",
	},
	{
		name: "rp-3rdparty-init-login",
		plan: "oidcc-client-test-3rd-party-init-login-test-plan",
		variant: RP_CODE_BASIC,
		config: "configs/openid-client-rp/oidcc-client-3rd-party-init-login.json",
	},
	// ---- suite vs suite: our OP tests against our own emulated OP (RP test module as the OP) ----
	{
		name: "suite-vs-suite",
		plan: "oidcc-basic-certification-test-plan",
		variant: DISCOVERY_DYNAMIC,
		config: "configs/suite-vs-suite/oidcc-basic.json",
		// the emulated OP is the RP tests' OP with oidcc-client-test's options (tests/suite-target.ts); what it cannot
		// do is skipped here, what it does differently is in configs/expected-failures/suite-vs-suite.json
		skipModules: {
			"oidcc-refresh-token": "the emulated OP knows one registered client; this module registers a second one",
			"oidcc-response-type-missing": INVALID_REQUEST_500 + " instead of an error redirect",
			"oidcc-ensure-registered-redirect-uri": INVALID_REQUEST_500 + " instead of an error page",
			"oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported": REQUEST_OBJECT_500,
			"oidcc-ensure-request-object-with-redirect-uri": REQUEST_OBJECT_500,
			"oidcc-claims-essential":
				"the emulated OP fails an authorization request with a claims parameter in the query (UPSTREAM: its claims checks read the parameter as a JSON object without parsing it) and answers with a 500 server_error",
		},
	},
];

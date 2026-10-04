/**
 * The test plans and the CI matrix.
 *
 * `plans`: every plan this suite implements - its spec file (one `test()` per module, tests/op/*.spec.ts for the
 * OP plans, tests/rp/*.spec.ts for the RP plans), its modules, and the variant parameters the plan leaves to the
 * user (upstream's values; the spec's `test.use({ plan })` fixes the others). playwright.config.ts runs the spec of
 * the selected plan, `openid-conformance list` prints this table.
 *
 * `projects`: a plan, the variant selection and the test configuration file (which also names the implementation
 * under test to start), and the browsers it runs on. Every (project, browser) pair of {@link matrix} is a GitHub
 * Actions job (.github/workflows/ci.yml reads them from `openid-conformance projects --json`). Mirrors upstream
 * `.gitlab-ci/run-tests.sh` (makeOidccTest / makeClientTest / local provider runs).
 *
 * `browsers`: the browsers the suite drives (CONFORMANCE_BROWSER, `ci|run --browser`); playwright.config.ts turns the
 * name into the Playwright project's `use`.
 */

/**
 * chromium: Playwright's headless Chromium shell (the default); firefox, webkit (Safari's engine): Playwright's
 * builds; chrome-mobile: Chromium emulating a Pixel 7 (mobile viewport and user agent, touch)
 */
export const browsers = ["chromium", "firefox", "webkit", "chrome-mobile"] as const;
export type BrowserName = (typeof browsers)[number];
export const DEFAULT_BROWSER: BrowserName = "chromium";

export function isBrowserName(name: string): name is BrowserName {
	return (browsers as readonly string[]).includes(name);
}

/**
 * The Playwright project (and report / artifact) name of a project run: the project's name, suffixed with the
 * browser unless it is the default one
 */
export function runName(project: string, browser: BrowserName): string {
	return browser === DEFAULT_BROWSER ? project : `${project}-${browser}`;
}

const SERVER_METADATA = ["static", "discovery"];
const CLIENT_REGISTRATION = ["static_client", "dynamic_client"];
const RESPONSE_TYPE = ["code", "id_token", "id_token token", "code id_token", "code token", "code id_token token"];
const RESPONSE_MODE = ["default", "form_post"];
const REQUEST_TYPE = ["plain_http_request", "request_object", "request_uri"];
/** upstream ClientAuthType (the RP plans) */
const CLIENT_AUTH_TYPE = [
	"none",
	"client_secret_basic",
	"client_secret_post",
	"client_secret_jwt",
	"private_key_jwt",
	"tls_client_auth",
	"self_signed_tls_client_auth",
];

export interface Plan {
	/** upstream's displayName */
	title: string;
	/** the Playwright spec file with the plan's `test.describe` */
	spec: string;
	/** the test modules (upstream testName) */
	modules: string[];
	/** the variant parameters the user selects (CONFORMANCE_VARIANT, `run --variant k=v`) and upstream's values */
	variants: Record<string, string[]>;
}

/** The module lists of the plans the form post plans repeat with response_mode=form_post */
const BASIC_MODULES = [
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
];
const IMPLICIT_MODULES = [
	"oidcc-server",
	"oidcc-idtoken-signature",
	"oidcc-ensure-request-without-nonce-fails",
	"oidcc-scope-profile",
	"oidcc-scope-email",
	"oidcc-scope-address",
	"oidcc-scope-phone",
	"oidcc-scope-all",
	"oidcc-alternate-happy-flow",
	"oidcc-display-page",
	"oidcc-display-popup",
	"oidcc-prompt-login",
	"oidcc-prompt-none-not-logged-in",
	"oidcc-prompt-none-logged-in",
	"oidcc-max-age-1",
	"oidcc-max-age-10000",
	"oidcc-ensure-request-with-unknown-parameter-succeeds",
	"oidcc-id-token-hint",
	"oidcc-login-hint",
	"oidcc-ui-locales",
	"oidcc-claims-locales",
	"oidcc-ensure-request-with-acr-values-succeeds",
	"oidcc-ensure-registered-redirect-uri",
	"oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported",
	"oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported",
	"oidcc-ensure-request-object-with-redirect-uri",
	"oidcc-claims-essential",
	"oidcc-userinfo-get",
	"oidcc-userinfo-post-header",
	"oidcc-userinfo-post-body",
	"oidcc-response-type-missing",
];
const HYBRID_MODULES = [
	"oidcc-server",
	"oidcc-response-type-missing",
	"oidcc-idtoken-signature",
	"oidcc-userinfo-get",
	"oidcc-userinfo-post-header",
	"oidcc-userinfo-post-body",
	"oidcc-ensure-request-without-nonce-fails",
	"oidcc-ensure-request-without-nonce-succeeds-for-code-flow",
	"oidcc-scope-profile",
	"oidcc-scope-email",
	"oidcc-scope-address",
	"oidcc-scope-phone",
	"oidcc-scope-all",
	"oidcc-alternate-happy-flow",
	"oidcc-display-page",
	"oidcc-display-popup",
	"oidcc-prompt-login",
	"oidcc-prompt-none-not-logged-in",
	"oidcc-prompt-none-logged-in",
	"oidcc-max-age-1",
	"oidcc-max-age-10000",
	"oidcc-ensure-request-with-unknown-parameter-succeeds",
	"oidcc-id-token-hint",
	"oidcc-login-hint",
	"oidcc-ui-locales",
	"oidcc-claims-locales",
	"oidcc-ensure-request-with-acr-values-succeeds",
	"oidcc-codereuse",
	"oidcc-codereuse-30seconds",
	"oidcc-ensure-registered-redirect-uri",
	"oidcc-server-client-secret-post",
	"oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported",
	"oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported",
	"oidcc-claims-essential",
	"oidcc-ensure-request-object-with-redirect-uri",
	"oidcc-refresh-token",
	"oidcc-ensure-request-with-valid-pkce-succeeds",
];

export const plans: Record<string, Plan> = {
	"oidcc-basic-certification-test-plan": {
		title: "OpenID Connect Core: Basic Certification Profile Authorization server test",
		spec: "tests/op/basic.spec.ts",
		modules: BASIC_MODULES,
		variants: { server_metadata: SERVER_METADATA, client_registration: CLIENT_REGISTRATION },
	},
	"oidcc-implicit-certification-test-plan": {
		title: "OpenID Connect Core: Implicit Certification Profile Authorization server test",
		spec: "tests/op/implicit.spec.ts",
		modules: IMPLICIT_MODULES,
		variants: { server_metadata: SERVER_METADATA, client_registration: CLIENT_REGISTRATION },
	},
	"oidcc-hybrid-certification-test-plan": {
		title: "OpenID Connect Core: Hybrid Certification Profile Authorization server test",
		spec: "tests/op/hybrid.spec.ts",
		modules: HYBRID_MODULES,
		variants: { server_metadata: SERVER_METADATA, client_registration: CLIENT_REGISTRATION },
	},
	"oidcc-formpost-basic-certification-test-plan": {
		title: "OpenID Connect Core: Form Post Basic Certification Profile Authorization server test",
		spec: "tests/op/formpost-basic.spec.ts",
		modules: BASIC_MODULES,
		variants: { server_metadata: SERVER_METADATA, client_registration: CLIENT_REGISTRATION },
	},
	"oidcc-formpost-implicit-certification-test-plan": {
		title: "OpenID Connect Core: Form Post Implicit Certification Profile Authorization server test",
		spec: "tests/op/formpost-implicit.spec.ts",
		modules: IMPLICIT_MODULES,
		variants: { server_metadata: SERVER_METADATA, client_registration: CLIENT_REGISTRATION },
	},
	"oidcc-formpost-hybrid-certification-test-plan": {
		title: "OpenID Connect Core: Form Post Hybrid Certification Profile Authorization server test",
		spec: "tests/op/formpost-hybrid.spec.ts",
		modules: HYBRID_MODULES,
		variants: { server_metadata: SERVER_METADATA, client_registration: CLIENT_REGISTRATION },
	},
	"oidcc-config-certification-test-plan": {
		title: "OpenID Connect Core: Config Certification Profile Authorization server test",
		spec: "tests/op/config.spec.ts",
		modules: ["oidcc-discovery-endpoint-verification"],
		variants: {},
	},
	"oidcc-dynamic-certification-test-plan": {
		title: "OpenID Connect Core: Dynamic Certification Profile Authorization server test",
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
		variants: { response_type: RESPONSE_TYPE },
	},
	"oidcc-rp-initiated-logout-certification-test-plan": {
		title: "OpenID Connect Core: Rp Initiated Logout Certification Profile Authorization server test",
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
		variants: { client_registration: CLIENT_REGISTRATION, response_type: RESPONSE_TYPE },
	},
	"oidcc-backchannel-rp-initiated-logout-certification-test-plan": {
		title: "OpenID Connect Core: Backchannel Rp Initiated Logout Certification Profile Authorization server test",
		spec: "tests/op/backchannel-logout.spec.ts",
		modules: ["oidcc-backchannel-logout-discovery-endpoint-verification", "oidcc-backchannel-rp-initiated-logout"],
		variants: { client_registration: CLIENT_REGISTRATION, response_type: RESPONSE_TYPE },
	},
	"oidcc-frontchannel-rp-initiated-logout-certification-test-plan": {
		title: "OpenID Connect Core: Frontchannel Rp Initiated Logout Certification Profile Authorization server test",
		spec: "tests/op/frontchannel-logout.spec.ts",
		modules: ["oidcc-frontchannel-logout-discovery-endpoint-verification", "oidcc-frontchannel-rp-initiated-logout"],
		variants: { client_registration: CLIENT_REGISTRATION, response_type: RESPONSE_TYPE },
	},
	"oidcc-session-management-certification-test-plan": {
		title: "OpenID Connect Core: Session Management Certification Profile Authorization server test",
		spec: "tests/op/session-management.spec.ts",
		modules: [
			"oidcc-session-management-discovery-endpoint-verification",
			"oidcc-session-management-rp-initiated-logout",
		],
		variants: { client_registration: CLIENT_REGISTRATION, response_type: RESPONSE_TYPE },
	},
	"oidcc-3rdparty-init-login-certification-test-plan": {
		title: "OpenID Connect Core: 3rd party initiated login Certification Profile Authorization server test",
		spec: "tests/op/3rdparty-init-login.spec.ts",
		modules: ["oidcc-3rd_party-init-login", "oidcc-3rd_party-init-login-nohttps"],
		variants: { response_type: RESPONSE_TYPE },
	},
	"oidcc-client-basic-certification-test-plan": {
		title: "OpenID Connect Core: Basic Certification Profile Relying Party Tests",
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
		variants: { client_registration: CLIENT_REGISTRATION, request_type: REQUEST_TYPE },
	},
	"oidcc-client-dynamic-certification-test-plan": {
		title: "OpenID Connect Core: Dynamic Certification Profile Relying Party Tests",
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
		variants: { client_auth_type: CLIENT_AUTH_TYPE, response_mode: RESPONSE_MODE },
	},
	"oidcc-client-rp-initiated-logout-rp-basic": {
		title: "OpenID Connect Core: RP Initiated Logout RP Certification Profile Relying Party Tests (Basic)",
		spec: "tests/rp/rp-initiated-logout.spec.ts",
		modules: [
			"oidcc-client-test-rp-init-logout",
			"oidcc-client-test-rp-init-logout-other-state",
			"oidcc-client-test-rp-init-logout-no-state",
		],
		variants: {
			client_auth_type: CLIENT_AUTH_TYPE,
			response_mode: RESPONSE_MODE,
			client_registration: CLIENT_REGISTRATION,
			request_type: REQUEST_TYPE,
		},
	},
	"oidcc-client-back-channel-logout-rp-basic": {
		title: "OpenID Connect Core: Back Channel Logout RP Certification Profile Relying Party Tests (Basic)",
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
		variants: {
			client_auth_type: CLIENT_AUTH_TYPE,
			response_mode: RESPONSE_MODE,
			client_registration: CLIENT_REGISTRATION,
			request_type: REQUEST_TYPE,
		},
	},
	"oidcc-client-front-channel-logout-rp-basic": {
		title: "OpenID Connect Core: Front Channel Logout RP Certification Profile Relying Party Tests (Basic)",
		spec: "tests/rp/frontchannel-logout.spec.ts",
		modules: ["oidcc-client-test-rp-frontchannel-rpinitlogout"],
		variants: {
			client_auth_type: CLIENT_AUTH_TYPE,
			response_mode: RESPONSE_MODE,
			client_registration: CLIENT_REGISTRATION,
			request_type: REQUEST_TYPE,
		},
	},
	"oidcc-client-rp-session-management-rp-basic": {
		title: "OpenID Connect Core: Session Management RP Certification Profile Relying Party Tests (Basic)",
		spec: "tests/rp/session-management.spec.ts",
		modules: ["oidcc-client-test-session-management"],
		variants: {
			client_auth_type: CLIENT_AUTH_TYPE,
			response_mode: RESPONSE_MODE,
			client_registration: CLIENT_REGISTRATION,
			request_type: REQUEST_TYPE,
		},
	},
	"oidcc-client-refreshtoken-test-plan": {
		title:
			"OpenID Connect Core Client Refresh Token Profile Tests: Relying party refresh token tests (not currently part of certification program)",
		spec: "tests/rp/refresh-token.spec.ts",
		modules: [
			"oidcc-client-test-refresh-token",
			"oidcc-client-test-refresh-token-invalid-issuer",
			"oidcc-client-test-refresh-token-invalid-sub",
		],
		variants: {
			client_auth_type: CLIENT_AUTH_TYPE,
			response_type: RESPONSE_TYPE,
			response_mode: RESPONSE_MODE,
			client_registration: CLIENT_REGISTRATION,
			request_type: REQUEST_TYPE,
		},
	},
	"oidcc-client-test-3rd-party-init-login-test-plan": {
		title: "OpenID Connect Core Client Login Tests: Relying party 3rd party initiated login tests",
		spec: "tests/rp/3rdparty-init-login.spec.ts",
		modules: ["oidcc-client-test-3rd-party-init-login"],
		variants: {
			client_auth_type: CLIENT_AUTH_TYPE,
			response_type: RESPONSE_TYPE,
			response_mode: RESPONSE_MODE,
			client_registration: CLIENT_REGISTRATION,
			request_type: REQUEST_TYPE,
		},
	},
};

export interface ConformanceProject {
	name: string;
	plan: string;
	variant: string;
	config: string;
	/**
	 * modules not run in this project: testName -> why (the Playwright skip reason; the `conformance` fixture of
	 * tests/fixtures.ts skips them)
	 */
	skipModules?: Record<string, string>;
	/**
	 * the browsers CI runs the project on (default: chromium only). All of them where the suite's browser is the one
	 * the implementation under test sees: the OP plans that drive a browser (authorization, logout, the
	 * check_session_iframe, front-channel logout and 3rd-party-initiated login pages) and the RP plans whose module the
	 * suite's browser visits (session management, front-channel logout, 3rd-party-initiated login); the other RP plans
	 * only see the RP's own HTTP client.
	 */
	browsers?: readonly BrowserName[];
	/**
	 * Playwright workers for the project (default 1). Modules are independent (each test has its own suite server,
	 * each worker its own target), so the OP projects run several at once; the bundled RP target serves one login
	 * at a time, so the RP projects stay at one.
	 */
	workers?: number;
}

const DISCOVERY_DYNAMIC = "[server_metadata=discovery][client_registration=dynamic_client]";
/** the variant the OP logout / session management / 3rd-party-initiated login plans run with */
const OP_CODE_BASIC =
	"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][server_metadata=discovery][client_registration=dynamic_client]";
/** the variant the RP dynamic / logout / session management / 3rd-party-initiated login plans run with */
const RP_CODE_BASIC =
	"[client_auth_type=client_secret_basic][response_type=code][response_mode=default][request_type=plain_http_request][client_registration=dynamic_client]";

export const projects: ConformanceProject[] = [
	// ---- OP plans against panva oidc-provider ----
	{
		name: "op-basic-static",
		plan: "oidcc-basic-certification-test-plan",
		variant: "[server_metadata=discovery][client_registration=static_client]",
		config: "configs/oidc-provider/oidcc-basic-static.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-basic-dynamic",
		plan: "oidcc-basic-certification-test-plan",
		variant: DISCOVERY_DYNAMIC,
		config: "configs/oidc-provider/oidcc-basic-dynamic.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-implicit",
		plan: "oidcc-implicit-certification-test-plan",
		variant: DISCOVERY_DYNAMIC,
		config: "configs/oidc-provider/oidcc-implicit.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-hybrid",
		plan: "oidcc-hybrid-certification-test-plan",
		variant: DISCOVERY_DYNAMIC,
		config: "configs/oidc-provider/oidcc-hybrid.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-formpost-basic",
		plan: "oidcc-formpost-basic-certification-test-plan",
		variant: DISCOVERY_DYNAMIC,
		config: "configs/oidc-provider/oidcc-formpost-basic.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-formpost-implicit",
		plan: "oidcc-formpost-implicit-certification-test-plan",
		variant: DISCOVERY_DYNAMIC,
		config: "configs/oidc-provider/oidcc-formpost-implicit.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-formpost-hybrid",
		plan: "oidcc-formpost-hybrid-certification-test-plan",
		variant: DISCOVERY_DYNAMIC,
		config: "configs/oidc-provider/oidcc-formpost-hybrid.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-config",
		plan: "oidcc-config-certification-test-plan",
		variant: "",
		config: "configs/oidc-provider/oidcc-config.json",
		// discovery only, no browser
	},
	{
		name: "op-dynamic",
		plan: "oidcc-dynamic-certification-test-plan",
		variant: "[response_type=code][client_auth_type=client_secret_basic][response_mode=default]",
		config: "configs/oidc-provider/oidcc-dynamic.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-rp-initiated-logout",
		plan: "oidcc-rp-initiated-logout-certification-test-plan",
		variant: OP_CODE_BASIC,
		config: "configs/oidc-provider/oidcc-rp-initiated-logout.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-backchannel-logout",
		plan: "oidcc-backchannel-rp-initiated-logout-certification-test-plan",
		variant: OP_CODE_BASIC,
		config: "configs/oidc-provider/oidcc-backchannel-logout.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-frontchannel-logout",
		plan: "oidcc-frontchannel-rp-initiated-logout-certification-test-plan",
		variant: OP_CODE_BASIC,
		config: "configs/oidc-provider/oidcc-frontchannel-logout.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-session-management",
		plan: "oidcc-session-management-certification-test-plan",
		variant: OP_CODE_BASIC,
		config: "configs/oidc-provider/oidcc-session-management.json",
		browsers,
		workers: 3,
	},
	{
		name: "op-3rdparty-init-login",
		plan: "oidcc-3rdparty-init-login-certification-test-plan",
		variant: OP_CODE_BASIC,
		config: "configs/oidc-provider/oidcc-3rdparty-init-login.json",
		browsers,
		workers: 3,
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
		browsers,
	},
	{
		name: "rp-session-management",
		plan: "oidcc-client-rp-session-management-rp-basic",
		variant: RP_CODE_BASIC,
		config: "configs/openid-client-rp/oidcc-client-session-management.json",
		browsers,
	},
	{
		name: "rp-refresh-token",
		plan: "oidcc-client-refreshtoken-test-plan",
		variant: RP_CODE_BASIC,
		config: "configs/openid-client-rp/oidcc-client-refreshtoken.json",
	},
	{
		name: "rp-3rdparty-init-login",
		plan: "oidcc-client-test-3rd-party-init-login-test-plan",
		variant: RP_CODE_BASIC,
		config: "configs/openid-client-rp/oidcc-client-3rd-party-init-login.json",
		browsers,
	},
	// ---- suite vs suite: our OP tests against our own emulated OP (RP test module as the OP) ----
	{
		name: "suite-vs-suite",
		plan: "oidcc-basic-certification-test-plan",
		variant: DISCOVERY_DYNAMIC,
		config: "configs/suite-vs-suite/oidcc-basic.json",
		browsers,
		workers: 3,
		// the emulated OP is the RP tests' OP with oidcc-client-test's options, answering as an OP under test
		// (tests/suite-target.ts); what it does differently is in configs/expected-failures/suite-vs-suite.json
	},
];

/** The CI matrix: every project on each of its browsers */
export function matrix(): { project: string; browser: BrowserName }[] {
	return projects.flatMap((p) => (p.browsers ?? [DEFAULT_BROWSER]).map((browser) => ({ project: p.name, browser })));
}

/**
 * The same pairs grouped by browser, in the order of {@link browsers}: what .github/workflows/ci.yml runs as one
 * conformance workflow per browser, each with its own project matrix
 */
export function matrixByBrowser(): Record<BrowserName, string[]> {
	const byBrowser = Object.fromEntries(browsers.map((b) => [b, [] as string[]])) as Record<BrowserName, string[]>;
	for (const { project, browser } of matrix()) {
		byBrowser[browser].push(project);
	}
	return byBrowser;
}

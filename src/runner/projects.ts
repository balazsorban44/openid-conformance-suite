/**
 * The test plans and the CI matrix.
 *
 * `plans`: every plan this suite implements - its spec file (one `test()` per module, tests/op/*.spec.ts for the
 * OIDCC OP plans, tests/fapi2/*.spec.ts for the FAPI 2.0 OP plans, tests/rp/*.spec.ts for the RP plans), its
 * modules (all of upstream's, the ones not ported yet listed as `TODO(port)` at the end of the spec), and the
 * variant parameters the plan leaves to the
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

/** upstream FAPI2 variants (the OP plans); the port covers the first value of each (see src/op/op.ts Fapi2Variant) */
const FAPI2_CLIENT_AUTH_TYPE = ["private_key_jwt", "mtls"];
const FAPI2_SENDER_CONSTRAIN = ["dpop", "mtls"];
const FAPI2_PROFILE = [
	"plain_fapi",
	"consumerdataright_au",
	"openbanking_brazil",
	"connectid_au",
	"cbuae",
	"openbanking_chile",
	"ksa",
	"fapi_client_credentials_grant",
];
const FAPI2_OPENID = ["openid_connect", "plain_oauth"];
const FAPI2_REQUEST_METHOD = ["unsigned", "signed_non_repudiation"];
const FAPI2_RESPONSE_MODE = ["plain_response", "jarm"];
const FAPI2_AUTHORIZATION_REQUEST_TYPE = ["simple", "rar"];
const FAPI2_GRANT_MANAGEMENT = ["disabled", "enabled"];

/**
 * The modules of upstream FAPI2MessageSigningFinalTestPlan.testModules, in its order; the security profile plan
 * is this list without the modules that need a signed request object
 */
const FAPI2_MESSAGE_SIGNING_MODULES = [
	// Normal well behaved client cases
	"fapi2-security-profile-final-discovery-end-point-verification",
	"fapi2-security-profile-final-happy-flow",
	"fapi2-security-profile-final-user-rejects-authentication",
	"fapi2-security-profile-final-ensure-request-object-with-multiple-aud-succeeds",
	"fapi2-security-profile-final-ensure-authorization-request-without-state-success",
	"fapi2-security-profile-final-ensure-authorization-request-without-nonce-success",
	"fapi2-security-profile-final-ensure-authorization-request-with-64-char-nonce-success",
	"fapi2-security-profile-final-ensure-other-scope-order-succeeds",
	"fapi2-security-profile-final-test-claims-parameter-identity-claims",
	"fapi2-security-profile-final-access-token-type-header-case-sensitivity",
	"fapi2-security-profile-final-ensure-request-object-with-nbf-8-seconds-in-the-future-is-accepted",
	// DPoP tests
	"fapi2-security-profile-final-check-dpop-proof-nbf-exp",
	"fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-before-succeeds",
	"fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-after-succeeds",
	// DPop Authorization Code Binding negative tests
	"fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails",
	"fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt",
	"fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-jkt",
	"fapi2-security-profile-final-ensure-dpopproof-at-par-endpoint-binding-success",
	"fapi2-security-profile-final-ensure-dpop-auth-code-binding-success",
	// Possible failure case
	"fapi2-security-profile-final-ensure-different-nonce-inside-and-outside-request-object",
	"fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object",
	"fapi2-security-profile-final-ensure-authorization-request-with-long-nonce",
	"fapi2-security-profile-final-ensure-authorization-request-with-long-state",
	// Negative tests for request objects
	"fapi2-security-profile-final-ensure-request-object-without-exp-fails",
	"fapi2-security-profile-final-ensure-request-object-without-nbf-fails",
	"fapi2-security-profile-final-state-only-outside-request-object-not-used",
	"fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails",
	"fapi2-security-profile-final-ensure-expired-request-object-fails",
	"fapi2-security-profile-final-ensure-request-object-with-bad-aud-fails",
	"fapi2-security-profile-final-ensure-request-object-with-exp-over-60-fails",
	"fapi2-security-profile-final-australia-connectid-ensure-request-object-with-exp-over-10-fails",
	"fapi2-security-profile-final-ensure-request-object-with-nbf-over-60-fails",
	"fapi2-security-profile-final-australia-connectid-ensure-request-object-with-nbf-over-15-fails",
	"fapi2-security-profile-final-ksa-ensure-request-object-with-exp-over-10-fails",
	"fapi2-security-profile-final-ksa-ensure-request-object-with-nbf-over-10-fails",
	"fapi2-security-profile-final-ensure-signed-request-object-with-RS256-fails",
	"fapi2-security-profile-final-ensure-request-object-signature-algorithm-is-not-none",
	"fapi2-security-profile-final-ensure-request-object-with-invalid-signature-fails",
	"fapi2-security-profile-final-ensure-matching-key-in-authorization-request",
	"fapi2-security-profile-final-ensure-unsigned-request-at-par-endpoint-fails",
	// Negative tests for authorization request
	"fapi2-security-profile-final-ensure-registered-redirect-uri",
	"fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri",
	"fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails",
	"fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request",
	"fapi2-security-profile-final-ensure-response-type-code-idtoken-fails",
	"fapi2-security-profile-final-australia-connectid-ensure-invalid-purpose-fails",
	"fapi2-security-profile-final-ensure-response-type-token-fails",
	// Negative tests for token endpoint
	"fapi2-security-profile-final-ensure-client-id-in-token-endpoint",
	"fapi2-security-profile-final-ensure-holder-of-key-required",
	"fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client",
	"fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second",
	"fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code",
	// Private key specific tests
	"fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails",
	"fapi2-security-profile-final-ensure-client-assertion-in-token-endpoint",
	"fapi2-security-profile-final-ensure-client-assertion-with-exp-is-5-minutes-in-past-fails",
	"fapi2-security-profile-final-ensure-client-assertion-with-wrong-aud-fails",
	"fapi2-security-profile-final-ensure-client-assertion-with-no-sub-fails",
	"fapi2-security-profile-final-ensure-invalid-client-assertions-fail",
	"fapi2-security-profile-final-dpop-negative-tests",
	// Refresh token tests
	"fapi2-security-profile-final-refresh-token",
	"fapi2-security-profile-final-cdr-sharing-duration-zero",
	"fapi2-security-profile-final-cdr-negative-sharing-duration",
	"fapi2-security-profile-final-cdr-refresh-token-introspection-expiry",
	"fapi2-security-profile-final-cdr-arrangement-amendment",
	"fapi2-security-profile-final-cdr-unrecognised-arrangement-id",
	// OB Brazil specific tests
	"fapi2-security-profile-final-brazil-ensure-bad-payment-signature-fails",
	// ConnectID specific tests
	"fapi2-security-profile-final-australia-connectid-test-claims-parameter-idtoken-identity-claims",
	// PAR tests
	"fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds",
	"fapi2-security-profile-final-par-attempt-reuse-request_uri",
	"fapi2-security-profile-final-par-attempt-to-use-expired-request_uri",
	"fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client",
	"fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param",
	"fapi2-security-profile-final-par-attempt-invalid-http-method",
	// PKCE tests
	"fapi2-security-profile-final-par-ensure-pkce-required",
	"fapi2-security-profile-final-ensure-pkce-code-verifier-required",
	"fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected",
	"fapi2-security-profile-final-par-plain-pkce-rejected",
	"fapi2-security-profile-final-par-authorization-request-containing-request_uri",
	"fapi2-security-profile-final-par-without-duplicate-parameters",
	// Grant Management tests
	"fapi2-security-profile-final-grant-management-query-and-revoke",
	"fapi2-security-profile-final-grant-management-merge",
	"fapi2-security-profile-final-grant-management-replace",
	"fapi2-security-profile-final-grant-management-ensure-invalid-grant-id-fails",
	"fapi2-security-profile-final-grant-management-ensure-query-nonexistent-grant-fails",
	"fapi2-security-profile-final-grant-management-ensure-wrong-client-cannot-query-grant",
	"fapi2-security-profile-final-grant-management-ensure-wrong-client-cannot-revoke-grant",
];

/** upstream FAPI2SPFinalTestPlan.fapi2SPtestModules: the modules that require signing are removed */
const FAPI2_SIGNED_REQUEST_MODULES = [
	"fapi2-security-profile-final-ensure-request-object-with-multiple-aud-succeeds",
	"fapi2-security-profile-final-ensure-request-object-without-exp-fails",
	"fapi2-security-profile-final-ensure-request-object-without-nbf-fails",
	"fapi2-security-profile-final-ensure-expired-request-object-fails",
	"fapi2-security-profile-final-ensure-request-object-with-bad-aud-fails",
	"fapi2-security-profile-final-ensure-request-object-with-exp-over-60-fails",
	"fapi2-security-profile-final-australia-connectid-ensure-request-object-with-exp-over-10-fails",
	"fapi2-security-profile-final-ensure-request-object-with-nbf-over-60-fails",
	"fapi2-security-profile-final-australia-connectid-ensure-request-object-with-nbf-over-15-fails",
	"fapi2-security-profile-final-ksa-ensure-request-object-with-exp-over-10-fails",
	"fapi2-security-profile-final-ksa-ensure-request-object-with-nbf-over-10-fails",
	"fapi2-security-profile-final-ensure-request-object-with-nbf-8-seconds-in-the-future-is-accepted",
	"fapi2-security-profile-final-ensure-signed-request-object-with-RS256-fails",
	"fapi2-security-profile-final-ensure-request-object-signature-algorithm-is-not-none",
	"fapi2-security-profile-final-ensure-request-object-with-invalid-signature-fails",
	"fapi2-security-profile-final-ensure-matching-key-in-authorization-request",
	"fapi2-security-profile-final-ensure-unsigned-request-at-par-endpoint-fails",
	"fapi2-security-profile-final-par-authorization-request-containing-request_uri",
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

export const plans: Record<string, Plan> = {
	"oidcc-basic-certification-test-plan": {
		title: "OpenID Connect Core: Basic Certification Profile Authorization server test",
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
	"fapi2-security-profile-final-test-plan": {
		title: "FAPI2-Security-Profile-Final: Authorization server test",
		spec: "tests/fapi2/security-profile.spec.ts",
		modules: FAPI2_MESSAGE_SIGNING_MODULES.filter((m) => !FAPI2_SIGNED_REQUEST_MODULES.includes(m)),
		variants: {
			client_auth_type: FAPI2_CLIENT_AUTH_TYPE,
			sender_constrain: FAPI2_SENDER_CONSTRAIN,
			fapi_profile: FAPI2_PROFILE,
			openid: FAPI2_OPENID,
			authorization_request_type: FAPI2_AUTHORIZATION_REQUEST_TYPE,
			grant_management: FAPI2_GRANT_MANAGEMENT,
		},
	},
	"fapi2-message-signing-final-test-plan": {
		title: "FAPI2-Message-Signing-Final: Authorization server test",
		spec: "tests/fapi2/message-signing.spec.ts",
		modules: FAPI2_MESSAGE_SIGNING_MODULES,
		variants: {
			client_auth_type: FAPI2_CLIENT_AUTH_TYPE,
			sender_constrain: FAPI2_SENDER_CONSTRAIN,
			fapi_profile: FAPI2_PROFILE,
			openid: FAPI2_OPENID,
			fapi_request_method: FAPI2_REQUEST_METHOD,
			fapi_response_mode: FAPI2_RESPONSE_MODE,
			authorization_request_type: FAPI2_AUTHORIZATION_REQUEST_TYPE,
			grant_management: FAPI2_GRANT_MANAGEMENT,
		},
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
/** the FAPI 2 variant the port covers (src/op/op.ts Fapi2Variant) */
const FAPI2_PRIVATE_KEY_DPOP =
	"[client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][openid=openid_connect][authorization_request_type=simple][grant_management=disabled]";
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
	// ---- FAPI 2.0 plans against panva oidc-provider in its FAPI 2.0 profile (OIDC_PROVIDER_PROFILE=fapi2) ----
	{
		name: "fapi2-security-profile",
		plan: "fapi2-security-profile-final-test-plan",
		variant: FAPI2_PRIVATE_KEY_DPOP,
		config: "configs/oidc-provider/fapi2-security-profile.json",
		browsers,
		workers: 3,
	},
	{
		name: "fapi2-message-signing",
		plan: "fapi2-message-signing-final-test-plan",
		variant: FAPI2_PRIVATE_KEY_DPOP + "[fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response]",
		config: "configs/oidc-provider/fapi2-message-signing.json",
		browsers,
		workers: 3,
	},
	{
		name: "fapi2-message-signing-jarm",
		plan: "fapi2-message-signing-final-test-plan",
		variant: FAPI2_PRIVATE_KEY_DPOP + "[fapi_request_method=unsigned][fapi_response_mode=jarm]",
		config: "configs/oidc-provider/fapi2-message-signing.json",
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

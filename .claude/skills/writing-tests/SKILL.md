---
name: writing-tests
description: The design of this suite and how to extend it - explicit Playwright tests with helper functions (no class framework): the src/suite engine (log, checks, http, server, browser, config, target, report, and the Java/Nimbus emulation: jose-*, json, uri, errors), the src/op and src/rp helpers, the fixtures, how an upstream test module becomes a test and an upstream condition a check function, the porting rules (Gson/Nimbus/JDK/Spring mappings, UPSTREAM markers, the deliberate deviations), how to run one module, expected failures, plans and projects, the upstream.lock.json symbols, and the testing principles (Artem Zakharchenko) to follow. Read before writing, porting or reviewing any test or helper.
---

# Writing tests

The suite is a set of **Playwright spec files that read like the test they are**: one `test()` per upstream test
module, the steps of the flow visible in the test body. Upstream's Java classes (test modules, conditions,
sequences, the Environment, the util classes) are **not** mirrored as classes; they map to plain functions grouped
by concern. What stays identical to upstream is what a user sees: the log messages, severities, requirement tags,
block names, and the HTTP requests and responses.

```
src/suite/            the engine (no OIDC knowledge)
  log.ts              per-test event log (upstream entry shape), current test context, log.html, resultOf()
  conditions.ts       condition(), soft(), block(), skipped(), logModule(), ConditionFailed
  http.ts             request() (logged like upstream's HttpClient), endpointResponse(), jsonBody()
  server.ts           the suite's HTTP(S) server per test: waitFor(path), on(path), requestParts
  browser.ts          the config's `browser` automation (JSON tasks or a TS hook): visit(url)
  config.ts           config files, ${TARGET_URL}, `override`, globs
  target.ts           starts `target.command` on a free PORT
  jose.ts             keys, JWK sets (Nimbus member order), verifyJwsSignature(), signJwt(), parseJwt()
  jose-algorithms.ts  Nimbus algorithm families and lookups; upstream util/JWAUtil, util/JWSUtil
  jose-jwk.ts         Nimbus JWK / JWK set parsing and JSON form; upstream util/JWKUtil (lenient parsing, key scans)
  jose-jws.ts         Nimbus signers (createJWSSigner, rsaSigner, ...) and verifier checks (verifySignedJWT)
  jose-jwe.ts         Nimbus decrypters (createDecrypter); upstream util/JWEUtil
  jose-jwt.ts         Nimbus JWT parsing (parseSignedJWT, parseClaimsSet, ...); upstream util/JWTUtil (parseJWT, ...)
  json.ts             Gson / OIDFJSON (getString), Nimbus JSONObjectUtils, java.util.HashMap member order
  errors.ts           NamedError and the Java exceptions the checks catch (ParseException, JOSEException, ...)
  uri.ts              java.net.URI (parseJavaURI), Spring UriComponentsBuilder (toUriString), RedirectURIValidationUtil
  bcp47.ts            upstream util/Bcp47LocaleValidation + Bcp47SubtagRegistry (data/language-subtag-registry.txt)
  json-schema.ts      upstream util/validation/JsonSchemaValidation* (schemas in data/json-schemas/)
  expected.ts         expected-failures / expected-skips analysis (upstream run-test-plan.py)
  report.ts           ModuleReport + Outcome, the console output, summary.md, the Playwright reporter (results.json,
                      the job summary, ::error annotations)
  wait.ts             upstream's WaitFor* conditions (the only sleeps: the spec's timing is what is tested)
  random.ts, testing.ts (Vitest helpers: useTestLog(), useMswServer())
src/op/               helpers for testing an OpenID Provider, one file per concern
  op.ts               the Op / OpVariant types the `op` fixture provides (RegistrationOp: `registrationOp`)
  discovery.ts        server metadata (discovery / static) and its checks (CheckDisc*, shared by the discovery
                      verification modules)
  discovery-endpoint.ts  the discovery endpoint verification: OIDCCDiscoveryEndpointVerification's checks of the
                      metadata document, performEndpointVerification()
  jwks.ts             the OP's keys, validateJwks() (ValidateJwksSequence), kid checks
  registration.ts     dynamic registration, static clients, unregistration (Client, RegisteredClient)
  authorization.ts    request building, authorize() (browser + redirect_uri), response checks
  token.ts            code exchange + client authentication, token response checks, error checks
  id-token.ts         PerformStandardIdTokenChecks and the per-module id_token checks
  userinfo.ts         callProtectedResource(), the userinfo endpoint checks (signed userinfo, claims)
  endpoint.ts         checks shared by every endpoint response (status, content type, error fields)
  refresh-token.ts    the refresh_token grant (RefreshTokenRequestSteps, RefreshTokenRequestExpectingErrorSteps)
  request-object.ts   request objects by value / by reference (request, request_uri), unsigned or signed
  logout.ts           RP-initiated / back-channel / front-channel logout: end_session request, post logout redirect,
                      logout token and front-channel request checks, the first login of the logout modules
  session.ts          session management: session_state, the suite's session check pages (check_session_iframe)
  initiate-login.ts   third-party-initiated login: initiate_login_uri in the registration / client configuration
src/rp/               the emulated OP for testing a Relying Party, one file per concern
  op.ts               startEmulatedOp(): setup, the endpoints on the test's server, expect()/waitFor(), options (knobs)
  rp.ts               the `rp` fixture's object (start, driveClient, skipTest) and driveClient (client_driver)
  discovery.ts        the generated metadata (OIDCCGenerateServerConfiguration...), the discovery response
  jwks.ts             the OP's keys (OIDCCGenerateServerJWKs and variants, unusable extra keys), the jwks response
  registration.ts     the registration endpoint, client metadata checks, static clients, the client's keys
  authorization.ts    the authorization endpoint: request checks, code, response (query / fragment / form_post)
  token.ts            the token endpoint: client authentication, code exchange checks, token response
  id-token.ts         signing algorithm, id_token claims, at_hash/c_hash, signing, the negative tests' defects
  userinfo.ts         the user, the userinfo endpoint (bearer token checks, claims filtered by scope, signing)
  request-object.ts   request objects (request_type request_object / request_uri): fetching, claim and signature checks
  logout.ts           end_session_endpoint, logout_token to the backchannel_logout_uri, the front-channel logout page,
                      the post_logout_redirect_uri redirect (AbstractOIDCCClientLogoutTest)
  session.ts          session_state, sid, the check_session_iframe and get_session_state (Session Management)
  webfinger.ts        WebFinger issuer discovery (/.well-known/webfinger on the test's server)
tests/fixtures.ts     the `test` with the `op`, `registrationOp`, `client`, `client2`, `configureClient`, `rp`, `variant`,
                      `plan` fixtures, and `skipTest(reason)`
tests/suite-target.ts suite-vs-suite: the emulated OP the `suiteTarget` fixture starts for an OP test (`suite_target`)
tests/op/*.spec.ts    one file per OP plan (basic, implicit, hybrid, formpost-basic, formpost-implicit,
                      formpost-hybrid, config, dynamic, rp-initiated-logout, backchannel-logout, frontchannel-logout,
                      session-management, 3rdparty-init-login); tests/op/shared.ts: the bodies of modules that are in
                      several plans (oidcc-server, the scope, userinfo and prompt modules, oidcc-refresh-token, ...)
                      and the pieces of AbstractOIDCCServerTest's flow for every response type
                      (completeAuthorizationFlow = handleAuthorizationEndpointResponse + exchangeAuthorizationCode +
                      userinfoEndpointTests)
tests/rp/*.spec.ts    one file per RP plan (basic, dynamic, rp-initiated-logout, backchannel-logout,
                      frontchannel-logout, session-management, 3rdparty-init-login); tests/rp/shared.ts: the bodies
                      of modules that are in several plans (each spec registers them with its title and upstream
                      comment) and the emulated OP options of each RP module (emulatedOpModules, for suite-vs-suite)
src/runner/projects.ts `plans` (plan -> title, spec file, modules, user-selectable variants) and `projects` (the CI
                      matrix: plan, variant, config, skipModules); src/runner/list.ts: `openid-conformance list`
bin/cli.ts            the CLI (list, run, ci, projects); playwright.config.ts picks the selected plan's spec
scripts/              upstream-lock-symbols.ts, sync-upstream.ts, log-fingerprint.ts
```

File names are kebab-case. A helper file groups everything about one concern; do not create a file per check.
Functions, not classes with static methods; a class only where something has state (a `JavaLocale`, a
`JWEDecrypter`, the `JsonSchemaValidation` of one schema).

## Principles (Artem Zakharchenko's testing fundamentals, applied here)

1. **The golden rule of assertions**: a test must fail if, and only if, the intention behind the system is not
   met. Every failure points at OP/RP behaviour that violates the spec, never at suite internals. Checks state the
   spec intention in their message and cite the requirement (`OIDCC-3.1.3.7`).
2. **Intent over implementation**: the test title says what the OP/RP must do
   (`"oidcc-codereuse: a second token request with the same code is rejected with invalid_grant"`).
3. **Explicit over implicit**: the test body shows the flow (request, authorize, verify, exchange, userinfo).
   Helpers return values the test uses; fixtures declare what the test depends on. A helper may group checks
   that upstream always runs together (`checkAuthorizationResponse`, `performStandardIdTokenChecks`,
   `requestAuthorizationCode`), and its doc comment says which upstream method it is.
4. **Test at the boundary you own**: conformance tests talk real HTTP to the OP/RP and drive a real browser.
   Unit tests (Vitest) cover helpers; where a helper makes HTTP calls, MSW intercepts at the network level
   (`useMswServer()`), never a stubbed `fetch` or module.
5. **Deterministic**: no sleeps; wait for the request (`server.waitFor`), the page, the element. Timeouts are
   explicit (`authorize()` waits 120 s for the redirect back).
6. **One behaviour per test, named after it.**

## Anatomy of an OP test (the code flow written out; tests/op/shared.ts has it for every response type)

```ts
import * as authz from "../../src/op/authorization.ts";
import * as discovery from "../../src/op/discovery.ts";
import { ensureHttpStatusCodeIs200 } from "../../src/op/endpoint.ts";
import * as idToken from "../../src/op/id-token.ts";
import * as token from "../../src/op/token.ts";
import * as userinfo from "../../src/op/userinfo.ts";
import { block, soft } from "../../src/suite/conditions.ts";
import { test } from "../fixtures.ts";

test.describe("oidcc-basic-certification-test-plan", () => {
	test.use({
		plan: {
			name: "oidcc-basic-certification-test-plan",
			variant: { response_type: "code", client_auth_type: "client_secret_basic", response_mode: "default" },
		},
	});

	// upstream: openid/OIDCCAuthCodeReuse.java (OP-OAuth-2nd)
	test("oidcc-codereuse: a second token request with the same code is rejected with invalid_grant", async ({
		op,
		client,
	}) => {
		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const { tokenRequest, tokens } = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const codeRequest = await token.createAuthorizationCodeRequest(op, client, code);
			const result = await token.requestAuthorizationCode(op, client, codeRequest);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return { tokenRequest: codeRequest, tokens: result };
		});

		await block("Userinfo endpoint tests", async () => {
			const url = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
			const res = await userinfo.callProtectedResource(url, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		await block("Attempting reuse of authorization code", async () => {
			const second = await token.callTokenEndpoint(op, tokenRequest);
			token.checkAuthorizationCodeReuseResponse(second);
		});
	});
});
```

- **Title**: `"<upstream testName>: <the behaviour>"`. The part before the first `:` is the module name: it selects
  the config `override`, is the `src` of the module's own log entries, the key in expected-failures lists and in
  `module-report.json`, and what `CONFORMANCE_MODULE` globs match. Put `// upstream: openid/<Module>.java`
  directly above the `test(` (scripts/upstream-lock-symbols.ts reads it).
- **Plan**: one `test.describe("<plan name>")` with `test.use({ plan: { name, variant } })`: the variant values the
  plan fixes. The user's selection (CONFORMANCE_VARIANT or the CI project) fills in the rest (`variant` fixture).
- **Not applicable** (upstream `@VariantNotApplicable`): the module is left out of the spec at collection time, as
  upstream's plan does not list it for that variant:
  `if (!variantNotApplicable(plan, { client_registration: ["static_client"] })) { test(...) }` (`selectedVariant(plan)`
  is the variant the spec runs with). A module list that fixes a response type upstream's annotation excludes simply
  does not register the module.
- **Response types** (upstream `responseType.includesCode()` / `includesIdToken()` / `includesToken()`):
  `completeAuthorizationFlow(op, client, request, response, opts)` (tests/op/shared.ts) runs AbstractOIDCCServerTest's
  flow for the variant's response_type: the authorization response from the query (code), the fragment (implicit,
  hybrid) or the form post (form_post), the code / access token / id_token it returns (the access token used at
  userinfo right away, in a "Userinfo endpoint tests" block that ends the "Verify authorization endpoint response"
  one as upstream's does), the token endpoint for the response types with code (with
  VerifyIdTokenSubConsistentHybridFlow when the authorization endpoint returned an id_token), and the userinfo request
  with the token endpoint's access token. It returns a `Flow` (`idToken`/`accessToken`: upstream env "id_token" /
  "access_token", the last ones received; `authorizationEndpointIdToken`, `tokenEndpointIdToken`, `tokens`,
  `tokenRequest`). A module's overrides are its options (`performIdTokenValidation`,
  `performAuthorizationEndpointIdTokenValidation`, `performAuthorizationCodeValidation`, `tokenRequest`,
  `additionalTokenEndpointResponseValidation`, `afterCallbackLocation`); a module body branches on the response type
  only where upstream's does (`responseTypeIncludes(op, "code")`).
- **Skipped at run time** (upstream `fireTestSkipped(msg)`): `skipTest(msg)` from tests/fixtures.ts logs the SKIPPED
  entry and ends the test (Playwright's skip); the expected skips of the configuration list such modules
  (`rp.skipTest(msg)` in RP tests).
- **Modules in several plans** (the same upstream class): the body is a function in tests/op/shared.ts taking the
  fixtures (`export async function oidccServer({ op, client }) { ... }`); each spec registers it with its own title
  and `// upstream:` comment: `test("oidcc-server: ...", oidccServer)`.
- **Blocks** (`block(name, fn)`): upstream's `startBlock(...)`/`endBlock()` and a Playwright step. Use upstream's
  block names and boundaries: expected-failures entries match on `current-block`. Blocks do not nest upstream
  (a new block replaces the open one); write them one after the other.
- **Branches** only where upstream's module has two valid outcomes (e.g. response-type-missing: an error redirect
  or an error page). Put such a decision into a named helper when it is more than one line
  (`token.checkAuthorizationCodeReuseResponse`).

## Anatomy of an RP test (from tests/rp/basic.spec.ts)

The suite plays the OP: the test starts the emulated OP with what this module does differently, makes the RP under
test log in against it, and follows the requests the RP sends. The checks upstream runs on those requests (the
`condition/as` classes) run inside the endpoint handlers, logged in their blocks ("Registration endpoint",
"Authorization endpoint", "Token endpoint", "Userinfo endpoint", ...).

```ts
import * as idToken from "../../src/rp/id-token.ts";
import { failTest } from "../../src/rp/op.ts";
import { test } from "../fixtures.ts";

// upstream: openid/client/OIDCCClientTestInvalidAudInIdToken.java (rp-id_token-aud)
test("oidcc-client-test-invalid-aud: the RP rejects an id_token whose aud is not its client_id", async ({ rp }) => {
	const op = await rp.start({
		idTokenClaims: (claims) => idToken.addInvalidAudValueToIdToken(claims, "OIDCC-3.1.3.7", "OIDCC-2"),
		onUserinfoRequest: () =>
			failTest(
				"Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid aud claim.",
			),
	});
	const client = rp.driveClient(); // GET client_driver.startUrl: the RP starts logging in against op.issuer
	await op.clientRegistered(); // dynamic_client: the registration request; static_client: the configured client
	await op.expect("authorization");
	await op.expect("token");
	// the RP must reject the id_token and stop: no userinfo request within waitTimeoutSeconds
	await op.waitFor("userinfo", rp.waitTimeoutSeconds);
	await client; // the RP under test reports it finished (TEST-RUNNER entry)
});
```

- `rp.start(options)` (src/rp/op.ts `startEmulatedOp`): the setup upstream's `AbstractOIDCCClientTest.configure`
  logs (metadata, keys and their validation, the user, the static client) and the endpoints, served on the test's
  server: the issuer is `server.baseUrl + "/"` (`/test/a/<alias>/`). The options are upstream's overridable methods
  as plain values / callbacks, named after what they change: `serverConfiguration`, `serverJwks`, `signingAlg`,
  `registrationSteps`, `checkNonce`, `checkResponseType`, `checkAuthorizationRequest`,
  `allowMaxAgeZeroWithPromptNone`, `customizeAuthorizationResponse`, `idTokenClaims`, `signIdToken`,
  `idTokenSignature`, `onCodeExchange`, `onUserinfoRequest`, `userinfo`, `clientAuthType`, `onRequest` (before
  any endpoint handles a request: the module's checks on the order of requests, key rotation), `checkClientMetadata`,
  `checkRequestObject`, `authorizationBlock`, `validateWebfingerResource`. A callback calls the upstream condition
  functions itself (with upstream's requirements), so the test shows what is logged. The endpoints are served where
  the metadata says (a module that moves the issuer or the jwks_uri gets them there); `op.keys` may be replaced
  (key rotation) and `op.received(endpoint)` counts the answered requests (upstream's received<Endpoint>Request).
- `op.expect(endpoint)` resolves with `{ request, ... }` once the OP answered the next request to `endpoint`
  (`registration` -> `client`, `authorization` -> `authorization` state + `response` params, `token` -> `response`,
  `userinfo` -> `response`); it fails when the RP finished without sending one (the client driver call returned),
  after 60 s, or when a check failed while handling a request (upstream: the module stops). `discovery` and `jwks`
  are served whenever the RP asks and can be awaited too.
- `op.waitFor(endpoint, seconds)` is upstream's `startWaitingForTimeout`: the request or null when none came in
  time (or the RP finished). Use it where the RP may or must not continue; what an unexpected request means is an
  option: `onUserinfoRequest: () => failTest(msg)` (upstream throws TestFailureException in the handler) or
  `rp.skipTest(msg)` (upstream fireTestSkipped). A test whose upstream module finishes after a request ends with
  `await op.expect(<that endpoint>)`.
- Requests are handled one at a time (upstream's test lock), outside the test's Playwright steps; the test's
  `expect`/`waitFor` calls are the steps of the report.
- `rp.driveClient()` (the client driver contract, targets/openid-client-rp/README.md): GET
  `client_driver.startUrl` with issuer, module, variant, client_metadata_defaults, alias and a static client's
  credentials; logged under TEST-RUNNER. The call blocks until the RP has run its flow, so its return tells the OP
  that no further requests will come.
- Not supported yet by the emulated OP (they throw a TODO(port) error): client_secret_jwt / private_key_jwt /
  mTLS client authentication, encrypted userinfo responses, encrypted id_tokens and logout tokens, refresh tokens,
  the OP-initiated front-channel logout page. Add them to the concern file (a new endpoint: `serve(...)` in op.ts,
  its handler in the concern file, e.g. `src/rp/logout.ts` serves end_session_endpoint and the session pages); the
  Nimbus encrypters (JWEUtil.createEncrypter) would go into src/suite/jose-jwe.ts next to the decrypters.

## Fixtures (tests/fixtures.ts)

- `op: Op` (src/op/op.ts): `testName`, `testId`, `config` (`override` applied), `variant`, `metadata` (upstream
  env "server"), `jwks` ("server_jwks"), `baseUrl`, `redirectUri`, `server` (TestServer), `browser`, `log`.
  Setup logs what upstream's `AbstractOIDCCServerTest.configure` logs up to the client: CreateRedirectUri,
  Get{Dynamic,Static}ServerConfiguration, CheckServerConfiguration, ExtractTLSTestValuesFromServerConfiguration,
  `loadServerKeys()`.
- `configureClient(setup?: ClientSetup): Promise<RegisteredClient>`: the one way a client is set up (upstream
  configureClient / completeClientConfiguration), called in the test body where upstream configures the client.
  It registers the client (`registerClient`) or takes it from the config, runs SetScopeInClientConfigurationToOpenId
  and EnsureServerConfigurationSupports<auth type> (discovery only), and after the test unregisters every registered
  client, in the order they were set up (block "Unregister dynamically registered client"). Conditions upstream runs
  before the client is configured (configureClient overrides, e.g. CreatePostLogoutRedirectUri, or a precondition
  that skips the module) are simply called before it. `ClientSetup` (src/op/registration.ts) is what a module
  changes about its client; a setup shared by several clients is a `const` of that type:
  - `customize(registrationRequest)`: additions to the dynamic registration request (upstream
    createDynamicClientRegistrationRequest overrides: called after the OIDCC defaults, before it is sent; not for a
    static client);
  - `staticConfigKey`: the config key of a static client (e.g. `"client_secret_post"`; default `configKey`);
  - `completeClientConfiguration(op, client)`: the module's completeClientConfiguration, in place of the default
    SetScopeInClientConfigurationToOpenId (e.g. the offline_access scope of the refresh token modules);
  - `configKey: "client2"`: the second client of the multiple client modules (config `client2`; its unregistration
    block is prefixed "Second client: ");
  - `redirectUri`, `jwksUri`, `generateKeys`: a module that registers another redirect_uri (a query added), its keys
    by reference (the test serves them, `op.server.on("client1_jwks", ...)`) or other keys
    (`generateRS256ClientJWKsWithKeyID`); only for a dynamic client;
  - `checkClientAuthSupported: false`: the modules built on upstream's AbstractOIDCCDynamicRegistrationTest, whose
    client is registered and its scope set without EnsureServerConfigurationSupports<auth type>.
- `client` / `client2`: `configureClient()` / `configureClient({ configKey: "client2" })` run before the test body,
  for modules that use the default client(s). A `RegisteredClient` has `client` (upstream env "client"), `keys`
  (client_jwks: `{ jwks, publicJwks }` or null), `dynamic` and `registrationRequest` (the request sent, if dynamic).
- `registrationOp: RegistrationOp`: the `op` without the OP's keys (CreateRedirectUri, the metadata,
  CheckServerConfiguration), for the modules upstream builds on AbstractOIDCCDynamicRegistrationTest (logo_uri,
  policy_uri, tos_uri, sector_identifier_uri, the registrations expected to fail). `op` builds on it
  (ExtractTLSTestValuesFromServerConfiguration, the keys) and `configureClient` registers with it, so a test that
  asks for `registrationOp` and `configureClient` never fetches the OP's keys.
- `conformance` (testName, log, config, server, browser) without discovery or keys, for modules whose own flow
  fetches the configuration (the discovery-endpoint-verification modules call `getDynamicServerConfiguration`;
  oidcc-discovery-endpoint-verification then runs `performEndpointVerification()` from src/op/discovery-endpoint.ts).
- `rp: Rp` (src/rp/rp.ts): `testName`, `variant` (RpVariant), `config`, `waitTimeoutSeconds` (config
  `waitTimeoutSeconds`, default 5), `start(options)` -> `EmulatedOp` (also `rp.op`), `driveClient()`,
  `skipTest(reason)`. Uses the same per-test setup and after-test analysis as `op` (the `conformance` fixture);
  a client driver call still running when the test ends is aborted.
- `variant: OpVariant`, `plan: { name, variant }` (option). A plan whose module lists fix different variants
  (upstream ModuleListEntry) uses one nested `test.describe` with its own `test.use({ plan })` per list, titled after
  the variant it fixes (`"response_type=code token"`). A module the plan lists for several variants (oidcc-server
  for each hybrid response type) is registered in each describe; its module name is the same, the variant (and
  `module-report.json`'s `instance`, the describe's title) tells them apart: the console and the summary show such a
  module as `oidcc-server (response_type=code token)`, and expected failures / skips match on the variant.
- Worker scope: the config is loaded and `target` started once per worker, on a free port. Per test: a fresh log,
  a suite server on a free port (https with CONFORMANCE_TLS=1), the browser automation on Playwright's `context`.
- After the test the fixture attaches `log.json`, `log.html`, `module-report.json`, `target-output.txt`,
  screenshots, and runs the expected-failures analysis (src/suite/expected.ts): unexpected failures, warnings,
  skips, or expected ones that did not happen fail the test; a test stopped (by a thrown check) only by failures
  the config expects is marked "expected to fail" and passes. Any other exception is logged as a FAILURE entry and
  the module status is INTERRUPTED.
- **Outcome and output** (src/suite/report.ts, the only reporter in playwright.config.ts besides the HTML one).
  Every module has one `outcome` (`ModuleReport.outcome`): `passed`, `review`, `skipped`, `expected failure` /
  `expected warning` (all failures/warnings of the log are in the expected-failures list; the run is fine) or
  `failed` (anything unexpected, or a crash). "failed" never means an expected failure; counts are written
  "20 passed, 3 skipped, 1 expected failure". The console shows one line per module as it finishes
  (`<glyph> <module>  <duration>  <note>`: `✓` passed, `?` review, `-` skipped, `~` expected failure/warning,
  `✗` failed) and at the end `OK: <counts>` or `FAILED: <counts>` followed by each unexpected failure (condition,
  block, message, path of its `log.html`). `openid-conformance ci` on a GitHub runner also prints one `::error`
  annotation per failed module (at its `test()` line). `conformance-report/summary.md` (the same markdown is
  appended to the job summary file, `$GITHUB_STEP_SUMMARY`) is one short section per run: a heading with a
  green/red mark, the counts, the unexpected failures first, then per plan the variant most modules share, a table
  of what is not a plain pass (expected failures, skips with their reason, reviews; a "Variant differs" column only
  for modules that deviate from the plan's variant) and the passed modules as a list.
  `conformance-report/results.json` is an array of `ModuleReport`: `plan`, `testName`, `variant`, `variantString`,
  `testId`, `status` (FINISHED/INTERRUPTED), `result` (upstream's PASSED/WARNING/REVIEW/SKIPPED/FAILED), `ok`,
  `outcome`, `durationMs`, `analysis` (the expected-failures analysis: unexpected/expected failures and warnings
  with condition, block, message), `title`, `attachments` (paths of `log.html` / `log.json`), `skipReason`, `error`.
  Presentation only: it never changes what the conditions log.
- `skipModules` of the CI project (src/runner/projects.ts): the `conformance` fixture skips a listed module with the
  reason given there, so it applies to every spec.
- **suite-vs-suite** (`suiteTarget`, tests/suite-target.ts): a config with `suite_target` (configs/suite-vs-suite)
  runs the OP tests against this suite's own emulated OP. Per test, before `op` discovers the OP, the fixture starts
  `startEmulatedOp` (src/rp/op.ts) on a second suite server (alias `suite_target.alias`, same TLS setting) with an
  event log of its own, with the options of the RP module `suite_target.module` names (`emulatedOpModules` in
  tests/rp/shared.ts; `oidccClientTestOptions()` is also what tests/rp/basic.spec.ts starts), the variant
  `suite_target.variant` (parameters it leaves out follow the OP test's variant) and the config
  `suite_target.config`, and sets the module's `server.discoveryUrl` to it. The emulated OP's checks log into its
  own log (startEmulatedOp keeps the context it was started in for every request it serves), attached as
  `emulated-op-log.json` / `emulated-op-log.html`, and are not part of the module's expected-failures analysis. It
  serves any number of flows until the test ends and runs with `opUnderTest` (EmulatedOpOptions): a failed check
  on a request becomes the OAuth error response an OP gives (error redirect, error page, 400 / 401 JSON) instead of
  ending the test, several registered clients each keep their authorization / tokens / refresh token (`selectClient`),
  request objects by value or by reference are taken whatever the variant says, the user's auth_time is kept between
  flows (prompt=login and an exceeded max_age authenticate afresh, prompt=none without a session is login_required),
  an authorization code is exchanged once, and token responses carry expires_in and cache headers. The RP tests never
  set it, so their OP stays upstream's. What the emulated OP still does differently is in
  configs/expected-failures/suite-vs-suite.json. Modules that only use `conformance` (no `op`) do not get it.

## Checks (upstream conditions)

Each upstream condition is one function, named after it in camelCase, in the helper file for its concern, with a
doc comment `upstream: condition/<pkg>/<Name>.java`, upstream's messages (copied from the Java, typos included),
and the same log fields:

```ts
/** upstream: condition/client/ValidateIdTokenNonce.java */
export function validateIdTokenNonce(
	idToken: ParsedJwt,
	expectedNonce: string | null,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateIdTokenNonce", ...requirements);
	const nonce = stringClaim(idToken, "nonce");
	if (nonce == null && expectedNonce == null) {
		c.success("nonce is not in id_token, as expected.");
		return;
	}
	if (expectedNonce !== nonce) {
		c.failure("Nonce values mismatch", { actual: nonce, expected: expectedNonce });
	}
	c.success("Nonce values match", { nonce });
}
```

- `const c: Condition = condition(name, ...requirements)` - **annotate the type**: TypeScript only narrows after a
  `never`-returning method call when the receiver has an explicit type, so `c.failure(...)` then works as a guard.
- `c.success / info / warning / review / log(msg | fields, fields?)` record (upstream logSuccess / log);
  `c.failure(msg, fields)` records at the current severity and throws `ConditionFailed` (upstream
  `throw error(...)`); `c.failureFrom(msg, cause, fields)` adds error/error_class/cause; `c.logFailure` records a
  failure without throwing (checks that report several problems, then `failure()`).
- **Requirements** are the call site's (upstream passes them to `callAndContinueOnFailure(X, FAILURE, "OIDCC-2")`):
  take `...requirements` and let the caller (a group helper or the test) pass them. Upstream's call sites are the
  reference: same strings, same order.
- **Severity**: a plain call stops the test on failure (callAndStopOnFailure); `soft(() => check(...))` records
  and continues (callAndContinueOnFailure); `soft(fn, "warning")` / `soft(fn, "info")` record the failure as
  WARNING / INFO (upstream's onFail result). `soft` returns the check's value or undefined.
- **Skips** (upstream `skipIfMissing` / `skipIfElementMissing`): `skipped("ValidateAtHash", { object: "at_hash" },
"OIDCC-3.3.2.11")` logs upstream's INFO entry; the caller decides (no hidden environment).
- **Inputs are parameters, outputs return values.** Pass what the Java read from the environment (the parsed
  id_token, the request, the response); name types after upstream's env keys in doc comments
  (`AuthorizationResponse.params` = "authorization_endpoint_response").
- HTTP: `request(c.name, { url, method, headers, body })` logs "HTTP request"/"HTTP response" under the
  condition; `endpointResponse(name, res)` is upstream's `convertResponseForEnvironment` shape. A status is never
  an error by itself (Spring's 4xx/5xx exceptions are written out where upstream relied on them).
- Upstream quirks are kept and marked `UPSTREAM:` (e.g. EnsureIdTokenUpdatedAtValid reads the wrong object, the
  static claim list of EnsureIdTokenDoesNotContainNonRequestedClaims accumulates). Deliberate deviations are
  marked too and listed below (see "Deliberate deviations").
- Module log entries (not conditions): `logModule({ msg, ... })` logs under the test name ("Redirecting to
  authorization endpoint", "Authorization endpoint response captured").

### Adding a check (how an upstream condition becomes a function)

1. Get the upstream checkout at the pinned commit (`$UPSTREAM`, or `pnpm sync-upstream --fetch` into
   `.upstream/`) and read the Java class `src/main/java/net/openid/conformance/condition/<pkg>/<Name>.java` and its
   base classes (`AbstractValidateHash`, `AbstractEnsureHttpStatusCode`, ...).
2. Check whether the helper exists already (`grep -rn "upstream: condition/<pkg>/<Name>.java" src`). If not, add the
   function to the helper file for its concern (append at the end); an abstract base class becomes a shared helper
   with its own `upstream:` comment (e.g. `ensureHttpStatusCode` for AbstractEnsureHttpStatusCode).
3. Translate the body with the mappings below: `@PreEnvironment` inputs become parameters, `env.put...` outputs
   the return value, `throw error(msg, args(...))` `c.failure(msg, {...})`, `logSuccess` `c.success`. Copy every
   message, keep the order of checks and the null/empty semantics (missing vs JSON null).
4. Call it where upstream calls it (the module or sequence), with upstream's requirements and severity.
5. Unit test the logic that is not obvious (Vitest, `src/**/<file>.test.ts`; `useTestLog()`; `useMswServer()`
   for HTTP), asserting the entries (`src`, `msg`, `result`, `requirements`).
6. `pnpm lock-symbols` records the Java file -> function mapping in upstream.lock.json (CI checks it).

An upstream test module becomes a `test()` the same way: read the Java module and its base classes (what
`configure` / `start` / `performAuthorizationFlow` / `onPostAuthorizationFlowComplete` call, in which blocks), write
the flow in the test body with the helpers, keep the block names; `@VariantNotApplicable` leaves the module out of
the spec (`variantNotApplicable(plan, {...})`), `fireTestSkipped` is `skipTest`, `@PublishTestModule(testName)` is the
title before the `:`.

## Porting rules

Everything a user of the suite sees must be identical to upstream: messages (typos included), severities,
requirement tags, block names, the order of checks, the HTTP requests the suite sends and the responses it
serves. The code that produces them is free to differ.

### Java -> TypeScript

| Java                                                                     | TypeScript                                                                   |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `JsonObject` / `JsonArray` / `JsonElement` / `JsonNull`                  | plain JSON (`JsonObject`, `JsonArray`, `JsonValue`, `null` from json.ts)     |
| `o.get("k") == null` / `o.has("k")`                                      | `o["k"] == null` (missing or JSON null) / `Object.hasOwn(o, "k")`            |
| `OIDFJSON.getString(el)` (throws on another type)                        | `getString(el)` (json.ts), or the type check written out                     |
| `JsonParser.parseString(s)` / `.getAsJsonObject()`                       | `parseJson(s)` / `parseJsonObject(s)` (json.ts)                              |
| `el.equals(other)`                                                       | `jsonEquals(a, b)` (json.ts)                                                 |
| `Strings.isNullOrEmpty(s)` / `Objects.equals(a, b)` / `String.format`    | `!s` / `a === b` / template literal                                          |
| `Instant.now().getEpochSecond()`                                         | `Math.floor(Date.now() / 1000)`                                              |
| `BaseEncoding.base64Url()`, `MessageDigest.getInstance("SHA-256")`       | `Buffer...toString("base64url")`, `createHash("sha256")` (node:crypto)       |
| `new URI(s)` (accept/reject, host, port matter), `URISyntaxException`    | `parseJavaURI(s)`, `URISyntaxException` (uri.ts)                             |
| `UriComponentsBuilder.fromUriString(u).queryParam(k, v)...toUriString()` | `toUriString(u, [[k, v], ...])` (uri.ts)                                     |
| `s.getBytes(US_ASCII)`                                                   | `Buffer.from(toUsAscii(s), "latin1")` (src/rp/id-token.ts)                   |
| Spring `RestTemplate` call (`createRestTemplate(env)`)                   | `request(c.name, { url, method, headers, body })` (http.ts), logged the same |
| `RestClientResponseException` on 4xx/5xx (no custom error handler)       | `if (res.status >= 400) { ...the same failure... }`                          |
| `convertResponseForEnvironment(name, response)`                          | `endpointResponse(name, res)` (http.ts)                                      |
| `NullPointerException` / `ClassCastException` upstream would throw       | the same failure, with an `UPSTREAM:` comment (e.g. a `TypeError` message)   |

### Nimbus JOSE+JWT -> jose-*.ts

Where the Java calls Nimbus and its behaviour shows up in the log (messages, accepted inputs, JSON member order),
the suite emulates Nimbus (the version upstream's pom.xml pins, noted in jose-algorithms.ts) on top of `jose`.
Nimbus or JDK behaviour lives only in src/suite (jose-*.ts, json.ts, uri.ts, errors.ts), never inside a check:
look there first; if something is missing, add it there (faithful to the library source) with a Vitest test
that pins the result and the exception message.

| Nimbus                                                                                 | suite                                                                                      |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `JWTParser.parse(s)` / `JWTUtil.parseJWT(s)`                                           | `jwtParserParse(s)` / `parseJWT(s)` (adds upstream's character check) -> `JWT`             |
| `SignedJWT.parse(s)`, `JWEObject.parse(s)`                                             | `parseSignedJWT(s)`, `parseJWEObject(s)` (jose-jwt.ts; messages differ from `parseJWT`)    |
| `jwt instanceof EncryptedJWT`, `jwt.getHeader().toJSONObject()`, `jwt.serialize()`     | `jwt.type === "encrypted"`, `jwt.header`, `jwt.serialized`                                 |
| `JWTUtil.jwtClaimsSetAsJsonObject(jwt)` / `jwtStringToJsonObjectForEnvironment(s)`     | the same names in jose-jwt.ts; `parseJwt(token, client, keys)` (jose.ts) decrypts first    |
| `JWTClaimsSet.parse(json)` + `toJSONObject()`                                          | `parseClaimsSet(json, includeNullValues)` (jose-jwt.ts)                                    |
| `JWKSet.parse(json)` / `JWK.parse(json)`, `toPublicJWK()`, `isPrivate()`               | `parseJWKSet`, `parseJWK`, `toPublicJWK`, `isPrivate` (jose-jwk.ts), JSON-shaped           |
| a JWK as a Java key (`toRSAPublicKey()`, `toSecretKey()`, ...)                         | `await importKey(jwk, alg)` (jose-jwk.ts)                                                  |
| `jwkSet.toJSONObject(publicOnly)`                                                      | `jwkSetToJSONObject(jwks, publicOnly)` (jose-jwk.ts), `publicJwks()` / `privateJwks()`     |
| `JWKMatcher.forJWSHeader`, `AlternateJWSVerificationKeySelector.selectJWSJwks`         | `jwkMatcherForJWSHeader` (jose-jwk.ts), `selectJWSJwks(header, jwkSet)` (jose-jws.ts)      |
| `KeyType.forAlgorithm`, `Curve.forJWSAlgorithm`, `ECDSA.resolveAlgorithm`              | `keyTypeForAlgorithm`, `curvesForJWSAlgorithm`, `EC_CURVE_ALGORITHM` (jose-algorithms.ts)  |
| `JWSAlgorithm.Family.*`, `JWEAlgorithm.Family.*`, `EncryptionMethod.Family.*`          | `JWS_FAMILY_*`, `JWE_FAMILY_*`, `ENC_FAMILY_*` (jose-algorithms.ts)                        |
| `RSASSASigner`, `ECDSASigner`, `MACSigner`, `Ed25519Signer`, `DefaultJWSSignerFactory` | `rsaSigner`, `ecSigner`, `macSigner`, `ed25519Signer`, `createJWSSigner` -> `await sign()` |
| `jwt.verify(verifier)`                                                                 | `await verifySignedJWT(jwt, { jwk, key })` (jose-jws.ts)                                   |
| `JWEDecrypter` implementations, `JWEUtil.createDecrypter`                              | `createDecrypter(alg, key)` -> `await decrypter.decrypt(compact)` (jose-jwe.ts)            |
| `JSONObjectUtils.parse/getString/...`                                                  | `nimbusParseJsonObject`, `nimbusGetString`, ... (json.ts)                                  |
| a `HashMap` whose iteration order decides JSON member order                            | `JavaHashMap` / `javaHashMapOf` (json.ts, JDK 21 order)                                    |
| `java.text.ParseException`, `JOSEException`, `KeyLengthException`                      | the same classes, `isJOSEException(e)` (errors.ts)                                         |

jose is async: checks that sign, verify or decrypt are `async`. jose validates more strictly than Nimbus in places
(e.g. unsupported curves); where the Java leniently skipped keys, the emulation does the same explicitly.

### Marking differences from upstream

- `// UPSTREAM: <what Java does>` at every spot where the code knowingly behaves like questionable upstream code (a
  bug, a dead check, a misleading message) or cannot behave exactly like it (a `NullPointerException` that becomes a
  `TypeError`, a JDK/Spring behaviour with no JS equivalent). `grep -rn "UPSTREAM:" src tests` lists them all.
- A deliberate behaviour change is a deviation: comment it at the code site and add it to the list below.

### Deliberate deviations

Everything else behaves like upstream; these are the known, intentional differences (each is commented at the
code site):

- `toUriString` (src/suite/uri.ts) encodes `+` in query parameters as `%2B`. Spring leaves it alone, but every
  form-decoding server reads a literal `+` as a space, which broke suite-vs-suite with the client ids the RP tests
  generate.
- The scripted browser (src/suite/browser.ts) records a url as visited when the navigation starts (Java: after
  `driver.get()` returns). A user-driven browser records it before the RP redirects, which is what
  `oidcc-client-test-3rd-party-init-login` checks for.
- The emulated OP's check_session_iframe (src/rp/session.ts) splits the postMessage `"client_id session_state"` on
  the last space; upstream's template splits on the first one and breaks with client ids containing spaces.
- In suite-vs-suite (tests/suite-target.ts) the RP test module's emulated OP answers any number of flows until the
  OP test ends; upstream's module finishes after its own flow.
- The suite's server (src/suite/server.ts) adds `x-ssl-protocol` / `x-ssl-cipher` to incoming requests over TLS,
  which the nginx/apache proxy adds upstream.
- `oidcc-server-rotate-keys` (tests/op/dynamic.spec.ts) does not wait for the user to press 'Start' and logs a
  `TEST-RUNNER` INFO entry saying so (upstream's CI script `run-test-plan.py` starts it the same way).
- The emulated OP parses a `claims` query parameter as JSON (src/rp/authorization.ts `claimsParameter`). Upstream
  reads it as a JSON object without parsing the string, so an RP that sends one (OIDCC 5.5) gets a 500.
- Modules upstream marks `@VariantNotApplicable` are left out of the spec at collection time
  (`variantNotApplicable` / `selectedVariant` in tests/fixtures.ts) rather than skipped, as upstream's plan does not
  list them for that variant.

### Review checklist

- [ ] Every message string is identical (copy-paste; keep typos); the log fields have upstream's names.
- [ ] Every requirement tag is preserved at the same call; severities (`soft`, `soft(fn, "warning")`) unchanged.
- [ ] Block names and boundaries are upstream's (expected-failures entries match on them).
- [ ] Order of checks and of HTTP requests unchanged; null/empty semantics match (missing vs JSON null).
- [ ] No behaviour added, removed or "fixed"; questionable upstream behaviour has an `UPSTREAM:` comment.
- [ ] No Nimbus/JDK emulation inside a check: it comes from src/suite.
- [ ] `upstream:` comment on every ported function and test; `pnpm lock-symbols` run.

## The suite side of a flow

- `server.waitFor(path, respond)` resolves with the next request to `<baseUrl>/<path>` (upstream's requestParts:
  headers, query_string_params, method, request_url, body, body_json, body_form_params) after `respond` answered
  it; register it before triggering the request. `server.on(path, handler)` serves an endpoint persistently
  (the emulated OP of RP tests). Absolute `/.well-known/...` paths work too.
- `authz.authorize(op, request)` logs "Redirecting...", waits for the redirect_uri (answered with upstream's
  implicit-callback page, which posts the fragment back), awaits the browser automation and returns
  `{ params, query, fragment, form, method, headers }`. The config's automation must end with the "Verify
  Complete" task waiting for `#submission_complete`, as upstream's configs do. `authorizeExpectingErrorPageOrRedirect`
  is the variant for requests the OP may answer with an error page (a REVIEW placeholder filled by
  `update-image-placeholder`). With response_mode=form_post the OP's page posts the response with JavaScript; the
  form post plans' configs have an optional task that waits for the redirect_uri before "Verify Complete" (a fast
  browser is there already, Firefox may still be on the OP's page).
- `op.browser.visit(url, { method: "POST" })` drives any other front-channel URL (logout, 3rd-party login). To
  capture what the browser's trip causes, register the waits first and await them together:
  `const [redirect] = await Promise.all([op.server.waitFor("post_logout_redirect", page), op.browser.visit(url)])`
  (src/op/logout.ts: redirectToEndSessionEndpoint*, src/op/session.ts: checkSessionState). The `respond` handler of
  `waitFor` runs between the logged incoming request and response, where upstream's handleHttp logs its messages.
- Suite URLs the OP must call over https (backchannel_logout_uri, initiate_login_uri at oidc-provider) need
  CONFORMANCE_TLS=1, which `openid-conformance ci` sets; the server then adds x-ssl-protocol / x-ssl-cipher to incoming
  requests (EnsureIncomingTls*).

## Running

```bash
CONFORMANCE_PROJECT=op-basic-dynamic pnpm test tests/op/basic.spec.ts               # the spec, against the bundled OP
CONFORMANCE_PROJECT=op-basic-dynamic CONFORMANCE_TLS=1 pnpm test tests/op/basic.spec.ts -g "oidcc-codereuse:"
node bin/cli.ts ci --project op-basic-dynamic                                         # the whole project
node bin/cli.ts ci --project op-session-management --browser webkit                   # on another browser
CONFORMANCE_MODULE='oidcc-server' node bin/cli.ts ci --project op-basic-dynamic
pnpm test:unit                                                                        # Vitest
```

Fidelity: a refactor of the engine or the helpers must not change any log entry. Fingerprint the logs before and
after (`scripts/log-fingerprint.ts --out` on both test-results directories, then `--diff`); only moved entries
(concurrent browser and server entries interleave differently) may differ. See .claude/skills/run-conformance.

## Plans, modules and projects

`plans` in src/runner/projects.ts lists every plan: its title (upstream displayName), its spec file, its modules
and the variant parameters the user selects; playwright.config.ts runs the selected plan's spec and the CLI's
`list` prints the table. `projects` is the CI matrix: one GitHub Actions job per project and browser (`matrix()`).

Browsers: `CONFORMANCE_BROWSER` (`ci`/`run --browser`) is `chromium` (default, the headless shell), `firefox`,
`webkit` or `chrome-mobile` (Chromium with `devices["Pixel 7"]`); playwright.config.ts turns it into the Playwright
project's `use` and names the project `<project>-<browser>` when it is not chromium. A project's `browsers` lists
the browsers CI runs it on (chromium only without it): all four for the projects where the implementation under test
sees the suite's browser (the OP plans that drive a browser, suite-vs-suite, rp-session-management,
rp-frontchannel-logout, rp-3rdparty-init-login). The suite's side of a flow must work in all of them: drive pages
through `op.browser` / the config's tasks (never a browser-specific API), wait for URLs and elements rather than
for timings, and keep the pages the suite serves (implicit callback, RP iframes, front-channel logout) plain
HTML/JS that every engine runs. A new project where the browser matters gets `browsers` and must pass on each.

- A new module of an existing plan: write the test in the plan's spec (or in tests/op/shared.ts / tests/rp/shared.ts
  when several plans have it), add its name to the plan's `modules`, run the project, `pnpm lock-symbols`.
- A new plan: a spec file with its `test.describe` and `test.use({ plan })`, an entry in `plans`, a test
  configuration under `configs/` for the bundled target (and expected failures / skips if the target deviates), and
  a project in `projects`.

## Sync with upstream

`upstream.lock.json` `symbols` maps each upstream Java file a function, class or test ports to
`{ blob, loc, ts, symbol }` (several Java files per TS file). `pnpm sync-upstream --status` lists the symbols whose
Java changed upstream; `pnpm sync-upstream --diff src/op/id-token.ts#validateIdTokenNonce` shows the change for a
function (see .claude/skills/sync-upstream).

## Tooling

pnpm 12 (`packageManager`), `pnpm check` (tsc, oxlint, oxfmt), `pnpm test:unit` (Vitest + MSW), `pnpm test`
(Playwright), `node bin/cli.ts` / `pnpm exec openid-conformance` (commander CLI: list, run, ci, projects).
Targets get a free `PORT` (`target.url: "https://localhost:${PORT}"`, configs use `${TARGET_URL}`), and a free port
for every `${PORT_<NAME>}` the target mentions (passed as `PORT_<NAME>`, e.g. `"env": { "RP_HTTPS_PORT":
"${PORT_HTTPS}" }` for the RP's https listener), so workers and projects run in parallel.

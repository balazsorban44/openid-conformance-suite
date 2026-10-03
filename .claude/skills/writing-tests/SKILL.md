---
name: writing-tests
description: How this suite is written as explicit Playwright tests with helper functions (no class framework) - the src/suite engine (log, checks, http, server, browser, config, target, jose, report), the src/op helpers, the fixtures, how an upstream test module becomes a test and an upstream condition a check function, how to run one module, expected failures, the upstream.lock.json symbols, and the testing principles (Artem Zakharchenko) to follow. Read before writing or porting any test or helper.
---

# Writing tests

The suite is a set of **Playwright spec files that read like the test they are**: one `test()` per upstream test
module, the steps of the flow visible in the test body. Upstream's Java classes (test modules, conditions,
sequences, the Environment) are **not** mirrored as classes; they map to plain functions grouped by concern.

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
  expected.ts         expected-failures / expected-skips analysis (upstream run-test-plan.py)
  report.ts           ModuleReport, summary.md, the Playwright reporter (results.json, $GITHUB_STEP_SUMMARY)
  wait.ts             upstream's WaitFor* conditions (the only sleeps: the spec's timing is what is tested)
  random.ts, testing.ts (Vitest helpers: useTestLog(), useMswServer())
src/op/               helpers for testing an OpenID Provider, one file per concern
  op.ts               the Op / OpVariant types the `op` fixture provides
  discovery.ts        server metadata (discovery / static) and its checks
  jwks.ts             the OP's keys, validateJwks() (ValidateJwksSequence), kid checks
  registration.ts     dynamic registration, static clients, unregistration (Client, RegisteredClient)
  authorization.ts    request building, authorize() (browser + redirect_uri), response checks
  token.ts            code exchange + client authentication, token response checks, error checks
  id-token.ts         PerformStandardIdTokenChecks and the per-module id_token checks
  userinfo.ts         callProtectedResource()
  endpoint.ts         checks shared by every endpoint response (status, content type, error fields)
  refresh-token.ts    the refresh_token grant (RefreshTokenRequestSteps, RefreshTokenRequestExpectingErrorSteps)
  request-object.ts   unsigned request objects by value / by reference (request, request_uri)
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
  webfinger.ts        WebFinger issuer discovery (/.well-known/webfinger on the test's server)
tests/fixtures.ts     the `test` with the `op`, `client`, `client2`, `configureClient`, `rp`, `variant`, `plan` fixtures
tests/suite-target.ts suite-vs-suite: the emulated OP the `suiteTarget` fixture starts for an OP test (`suite_target`)
tests/op/*.spec.ts    one file per OP plan (basic, rp-initiated-logout, backchannel-logout, frontchannel-logout,
                      session-management, 3rdparty-init-login so far)
tests/rp/*.spec.ts    one file per RP plan (basic.spec.ts, dynamic.spec.ts); tests/rp/shared.ts: the bodies of
                      modules that are in several plans (each spec registers them with its title and upstream comment)
tests/plan.spec.ts    the old framework, for the modules not rewritten yet (see "Transition")
```

File names are kebab-case. A helper file groups everything about one concern; do not create a file per check.
New code never imports `src/framework`, `src/condition`, `src/sequence` or `src/openid` (they are being replaced);
`src/util` (Nimbus/JDK emulation, JWKUtil, JWTUtil, UriComponentsBuilder) may be reused.

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

## Anatomy of an OP test (from tests/op/basic.spec.ts)

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
- **Not applicable** (upstream `@VariantNotApplicable`): a nested `test.describe` with
  `test.skip(({ variant }) => variant.client_registration === "static_client", "not applicable to static clients")`.
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
- `rp.driveClient()` (port of the old runner's driveClient, targets/openid-client-rp/README.md): GET
  `client_driver.startUrl` with issuer, module, variant, client_metadata_defaults, alias and a static client's
  credentials; logged under TEST-RUNNER. The call blocks until the RP has run its flow, so its return tells the OP
  that no further requests will come.
- Not supported yet by the emulated OP (they throw a TODO(port) error): client_secret_jwt / private_key_jwt /
  mTLS client authentication, encrypted userinfo responses, encrypted id_tokens and logout tokens, refresh tokens,
  the OP-initiated front-channel logout page. Add them to the concern file (a new endpoint: `serve(...)` in op.ts,
  its handler in the concern file, e.g. `src/rp/logout.ts` serves end_session_endpoint and the session pages).

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
  - `completeClientConfiguration(op, client)`: runs after SetScopeInClientConfigurationToOpenId (e.g. the scope);
  - `configKey: "client2"`: the second client of the multiple client modules (config `client2`; its unregistration
    block is prefixed "Second client: ").
- `client` / `client2`: `configureClient()` / `configureClient({ configKey: "client2" })` run before the test body,
  for modules that use the default client(s). A `RegisteredClient` has `client` (upstream env "client"), `keys`
  (client_jwks: `{ jwks, publicJwks }` or null), `dynamic` and `registrationRequest` (the request sent, if dynamic).
- `conformance` (testName, log, config, server, browser) without discovery or keys, for modules whose own flow
  fetches the configuration (the discovery-endpoint-verification modules call `getDynamicServerConfiguration`).
- `rp: Rp` (src/rp/rp.ts): `testName`, `variant` (RpVariant), `config`, `waitTimeoutSeconds` (config
  `waitTimeoutSeconds`, default 5), `start(options)` -> `EmulatedOp` (also `rp.op`), `driveClient()`,
  `skipTest(reason)`. Uses the same per-test setup and after-test analysis as `op` (the `conformance` fixture);
  a client driver call still running when the test ends is aborted.
- `variant: OpVariant`, `plan: { name, variant }` (option). A plan whose module lists fix different variants
  (upstream ModuleListEntry) uses one nested `test.describe` with its own `test.use({ plan })` per list.
- Worker scope: the config is loaded and `target` started once per worker, on a free port. Per test: a fresh log,
  a suite server on a free port (https with CONFORMANCE_TLS=1), the browser automation on Playwright's `context`.
- After the test the fixture attaches `log.json`, `log.html`, `module-report.json`, `target-output.txt`,
  screenshots, and runs the expected-failures analysis (src/suite/expected.ts): unexpected failures, warnings,
  skips, or expected ones that did not happen fail the test; a test stopped (by a thrown check) only by failures
  the config expects is marked "expected to fail" and passes. Any other exception is logged as a FAILURE entry and
  the module status is INTERRUPTED.
- `skipModules` of the CI project (src/runner/projects.ts): the `conformance` fixture skips a listed module with the
  reason given there, so it applies to every spec (tests/plan.spec.ts does the same for the old framework).
- **suite-vs-suite** (`suiteTarget`, tests/suite-target.ts): a config with `suite_target` (configs/suite-vs-suite)
  runs the OP tests against this suite's own emulated OP. Per test, before `op` discovers the OP, the fixture starts
  `startEmulatedOp` (src/rp/op.ts) on a second suite server (alias `suite_target.alias`, same TLS setting) with an
  event log of its own, with the options of the RP module `suite_target.module` names (`emulatedOpModules` in
  tests/rp/shared.ts; `oidccClientTestOptions()` is also what tests/rp/basic.spec.ts starts), the variant
  `suite_target.variant` (parameters it leaves out follow the OP test's variant) and the config
  `suite_target.config`, and sets the module's `server.discoveryUrl` to it. The emulated OP's checks log into its
  own log (startEmulatedOp keeps the context it was started in for every request it serves), attached as
  `emulated-op-log.json` / `emulated-op-log.html`, and are not part of the module's expected-failures analysis. It
  serves any number of flows until the test ends; what it cannot serve is in the project's `skipModules`, what it does
  differently in configs/expected-failures/suite-vs-suite.json. Modules that only use `conformance` (no `op`) do not
  get it.

## Checks (upstream conditions)

Each upstream condition is one function, named after it in camelCase, in the helper file for its concern, with a
doc comment `upstream: condition/<pkg>/<Name>.java`, upstream's messages (copy them from the 1:1 TS port in
`src/condition/...`, which matches the Java), and the same log fields:

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
  marked too and listed in the commit message.
- Module log entries (not conditions): `logModule({ msg, ... })` logs under the test name ("Redirecting to
  authorization endpoint", "Authorization endpoint response captured").

### Adding a check

1. Find the Java class and the 1:1 port in `src/condition/<pkg>/<Name>.ts` (same messages). Read its base classes.
2. Add the function to the helper file for its concern (or a shared private helper for an abstract base class,
   e.g. `ensureHttpStatusCode` for AbstractEnsureHttpStatusCode, with its own `upstream:` comment).
3. Call it where upstream calls it, with upstream's requirements and severity.
4. Unit test the logic that is not obvious (Vitest, `src/**/<file>.test.ts`; `useTestLog()`; `useMswServer()`
   for HTTP), asserting the entries (`src`, `msg`, `result`, `requirements`).
5. `pnpm lock-symbols` records the Java file -> function mapping in upstream.lock.json (CI checks it).

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
  `update-image-placeholder`).
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
node bin/cli.ts ci --project op-basic-dynamic                                         # the whole project (new spec + plan.spec.ts)
CONFORMANCE_MODULE='oidcc-server' node bin/cli.ts ci --project op-basic-dynamic
pnpm test:unit                                                                        # Vitest
```

Fidelity: compare the condition entries with a baseline run of the old framework (`scripts/log-fingerprint.ts
--out` on both test-results directories, then `--diff`). Expected differences: the old framework's own entries
(Setup Done, Test has run to completion, Final environment) are gone, entries move where the flow is now
sequential (browser entries, setup checks run by the test where they are used).

## Transition

`portedPlans` in src/runner/projects.ts lists, per plan, the spec file and the modules it covers.
playwright.config.ts adds the spec to the selected project and tests/plan.spec.ts leaves those modules out, so a
CI project keeps running its whole plan. Porting a module: write the test, add the module to `portedPlans`, run
the project, diff the fingerprints against the old framework's run, `pnpm lock-symbols`.

## Sync with upstream

`upstream.lock.json` `symbols` maps each Java file to `{ blob, loc, ts, symbol }` (several Java files per TS file);
`files` still tracks the 1:1 ports. `pnpm sync-upstream --status` lists changed Java files of both;
`pnpm sync-upstream --diff src/op/id-token.ts#validateIdTokenNonce` shows the upstream change for a function.

## Tooling

pnpm 12 (`packageManager`), `pnpm check` (tsc, oxlint, oxfmt), `pnpm test:unit` (Vitest + MSW), `pnpm test`
(Playwright), `node bin/cli.ts` / `pnpm exec openid-conformance` (commander CLI: list, run, ci, projects).
Targets get a free `PORT` (`target.url: "https://localhost:${PORT}"`, configs use `${TARGET_URL}`), and a free port
for every `${PORT_<NAME>}` the target mentions (passed as `PORT_<NAME>`, e.g. `"env": { "RP_HTTPS_PORT":
"${PORT_HTTPS}" }` for the RP's https listener), so workers and projects run in parallel.

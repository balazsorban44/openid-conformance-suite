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
src/rp/               (to come) the emulated OP for RP tests and its request checks
tests/fixtures.ts     the `test` with the `op`, `client`, `client2`, `variant`, `plan` fixtures
tests/op/*.spec.ts    one file per OP plan (basic.spec.ts so far)
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

## Fixtures (tests/fixtures.ts)

- `op: Op` (src/op/op.ts): `testName`, `testId`, `config` (`override` applied), `variant`, `metadata` (upstream
  env "server"), `jwks` ("server_jwks"), `baseUrl`, `redirectUri`, `server` (TestServer), `browser`, `log`.
  Setup logs what upstream's `AbstractOIDCCServerTest.configure` logs up to the client: CreateRedirectUri,
  Get{Dynamic,Static}ServerConfiguration, CheckServerConfiguration, ExtractTLSTestValuesFromServerConfiguration,
  `loadServerKeys()`.
- `client` / `client2: RegisteredClient` = `{ client: Client (upstream env "client"), keys: { jwks, publicJwks } |
null (client_jwks), dynamic }`: registered (`registerClient`) or from the config, SetScopeInClientConfiguration,
  EnsureServerConfigurationSupports<auth type> (discovery only); a registered client is unregistered after the
  test in the block "Unregister dynamically registered client".
- `variant: OpVariant`, `plan: { name, variant }` (option).
- Worker scope: the config is loaded and `target` started once per worker, on a free port. Per test: a fresh log,
  a suite server on a free port (https with CONFORMANCE_TLS=1), the browser automation on Playwright's `context`.
- After the test the fixture attaches `log.json`, `log.html`, `module-report.json`, `target-output.txt`,
  screenshots, and runs the expected-failures analysis (src/suite/expected.ts): unexpected failures, warnings,
  skips, or expected ones that did not happen fail the test; a test stopped (by a thrown check) only by failures
  the config expects is marked "expected to fail" and passes. Any other exception is logged as a FAILURE entry and
  the module status is INTERRUPTED.

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
- `op.browser.visit(url, { method: "POST" })` drives any other front-channel URL (logout, 3rd-party login).

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
the project, diff the fingerprints against the old framework's run, `pnpm lock-symbols`. A project marked `legacy: true`
(suite-vs-suite: the emulated OP is an old-framework RP module) runs every module on the old framework.

## Sync with upstream

`upstream.lock.json` `symbols` maps each Java file to `{ blob, loc, ts, symbol }` (several Java files per TS file);
`files` still tracks the 1:1 ports. `pnpm sync-upstream --status` lists changed Java files of both;
`pnpm sync-upstream --diff src/op/id-token.ts#validateIdTokenNonce` shows the upstream change for a function.

## Tooling

pnpm 12 (`packageManager`), `pnpm check` (tsc, oxlint, oxfmt), `pnpm test:unit` (Vitest + MSW), `pnpm test`
(Playwright), `node bin/cli.ts` / `pnpm exec openid-conformance` (commander CLI: list, run, ci, projects).
Targets get a free `PORT` (`target.url: "https://localhost:${PORT}"`, configs use `${TARGET_URL}`), so workers and
projects run in parallel.

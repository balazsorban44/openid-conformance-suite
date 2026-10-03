---
name: writing-tests
description: The design of this suite as explicit Playwright tests with helper functions (no class framework) - how a conformance test module is written, how upstream conditions become check functions, the suite/op/rp helper layout, fixtures, logging, expected failures, and the testing principles (Artem Zakharchenko) to follow. Read before writing or porting any test or helper.
---

# Writing tests

The suite is a set of **Playwright spec files that read like the test they are**: one `test()` per upstream
test module, the steps of the flow visible in the test body, assertions explicit. Upstream's Java classes
(test modules, conditions, sequences, the Environment, builders) are **not** mirrored as classes; they map to
plain functions in a small number of files.

```
src/suite/      the engine: log + conditions, http, incoming server, browser automation, config, expected failures, report
src/op/         helpers for testing an OpenID Provider: discovery, registration, authorization, token, userinfo, id-token, jwks, logout, request-object
src/rp/         helpers for testing a Relying Party: the emulated OP (endpoints as functions) and its request checks
tests/op/*.spec.ts   one file per OP plan (basic, config, dynamic, rp-initiated-logout, backchannel-logout, frontchannel-logout, session-management, 3rdparty-init-login)
tests/rp/*.spec.ts   one file per RP plan
tests/fixtures.ts    the `op` / `rp` / `variant` fixtures
targets/        the implementations CI tests (oidc-provider OP, openid-client RP), one file each
configs/        test configurations, expected-failures, expected-skips
bin/cli.ts      the commander CLI
```

File names are kebab-case. Fewer, larger files are preferred over one file per concept; a helper module
groups everything about one concern (e.g. `src/op/id-token.ts` holds parsing, signature verification and every
id_token claim check).

## Principles (Artem Zakharchenko's testing fundamentals, applied here)

1. **The golden rule of assertions**: a test must fail if, and only if, the intention behind the system is not
   met. Every failure must point at the OP/RP behaviour that violates the spec, never at suite internals. Checks
   therefore state the spec intention in their message and cite the requirement (`OIDCC-3.1.3.7`).
2. **Intent over implementation**: a test describes what the OP/RP must do (`"oidcc-codereuse: a second token
request with the same code is rejected with invalid_grant"`), not how the suite does it.
3. **Explicit over implicit**: the test body shows the flow (discover, register, authorize, exchange, verify).
   No hidden state in `beforeEach`, no conditional logic in tests, no helper that silently asserts something the
   reader cannot see. Helpers return values the test uses; fixtures declare what the test depends on.
4. **Test at the boundary you own**: the suite talks real HTTP to the OP/RP and drives a real browser. Nothing
   is mocked in conformance tests. Unit tests (Vitest) cover helpers; where a helper makes HTTP calls, MSW
   intercepts at the network level instead of stubbing `fetch` or modules ("don't mock what you don't own").
5. **Deterministic**: no arbitrary sleeps; wait for the request, the page, the element. Timeouts are explicit
   and justified (the OP has 30 s to call the redirect_uri after a POST authorization request).
6. **One behaviour per test, named after it.** A plan file is a list of behaviours.

## Anatomy of an OP test

```ts
import { test, expect } from "../fixtures.ts";
import { soft } from "../../src/suite/conditions.ts";
import * as authz from "../../src/op/authorization.ts";
import * as token from "../../src/op/token.ts";
import * as idToken from "../../src/op/id-token.ts";
import * as userinfo from "../../src/op/userinfo.ts";

// upstream: openid/OIDCCServerTest.java
test("oidcc-server: the authorization code flow succeeds end to end", async ({ op, client }) => {
	const request = authz.request(op, client, { scope: "openid", state: random(), nonce: random() });
	const callback = await authz.authorize(op, request); // drives the browser, returns the redirect_uri parameters

	await test.step("verify the authorization response", () => {
		authz.checkStateInAuthorizationResponse(callback, request.state);
		soft(() => authz.checkForUnexpectedParametersInCallback(callback), "warning");
	});

	const tokens = await token.exchangeCode(op, client, callback.code, request);
	token.checkTokenResponse(tokens);

	const claims = await idToken.validate(tokens.id_token, { op, client, nonce: request.nonce });
	expect(claims.sub).toBeTruthy();

	const info = await userinfo.get(op, tokens.access_token);
	userinfo.checkSubMatches(info, claims);
});
```

- `op` (fixture): the OP under test — resolved configuration (`op.metadata`, `op.jwks`), the suite's own
  base url for callbacks, the browser automation from the config, the per-test event log. Created per test.
- `client` (fixture): the client to use — registered dynamically or taken from the config, per the
  `client_registration` variant. `client2` exists for modules that need two clients.
- `variant` (fixture): the resolved variant values (`response_type`, `client_auth_type`, ...).
- `test.step()` names the blocks (upstream's `startBlock`) so the Playwright report shows the flow.
- A check is a plain function named like the upstream condition (camelCase) that **records** a result in the
  test's log and **throws** on failure. `soft(fn, severity?)` records the failure and continues (upstream's
  `callAndContinueOnFailure`); a plain call stops the test (`callAndStopOnFailure`).

## Anatomy of an RP test

```ts
// upstream: openid/client/OIDCCClientTestInvalidSigRS256.java
test("oidcc-client-test-invalid-sig-rs256: the RP rejects an id_token with an invalid signature", async ({ rp }) => {
	rp.op.idToken.use({ corruptSignature: true });
	const run = await rp.start(); // asks the RP to log in against rp.op.issuer (client_driver)

	const registration = await run.expect("registration"); // the RP registered itself
	const authorization = await run.expect("authorization"); // and sent the user to the authorization endpoint
	await run.expect("token");
	await expect(run.userinfoRequested()).resolves.toBe(false); // the RP must stop after the bad id_token
	expect(run.outcome).toBe("rejected");
});
```

- `rp` (fixture): starts an emulated OP (`rp.op`) on a free port, exposes knobs to alter its behaviour per
  test, and drives the RP under test through `client_driver.startUrl`. `run.expect(endpoint)` resolves with
  the validated request when the RP calls that endpoint (or fails the test after the configured wait).
- The emulated OP's endpoint handlers live in `src/rp/emulated-op.ts`; its request checks (the upstream
  `condition/as` classes) in `src/rp/checks.ts`, each named after the upstream condition.

## Conditions (upstream `condition/*` classes)

Each upstream condition is one exported function with the same name in camelCase, a doc comment citing the
Java file, the same log messages, the same requirement tags, and the same default severity:

```ts
/** upstream: condition/client/ValidateIdTokenNonce.java */
export function validateIdTokenNonce(claims: IdTokenClaims, expected: string): void {
	const c = condition("ValidateIdTokenNonce", "OIDCC-3.1.3.7");
	if (claims.nonce !== expected) {
		c.failure("Nonce values mismatch", { expected, actual: claims.nonce });
	}
	c.success("Nonce values match");
}
```

- `condition(name, ...requirements)` binds the current test's log (AsyncLocalStorage, set by the fixture).
  `success` / `info` / `warning` record; `failure` records and throws `ConditionFailed`. Severity for
  `soft()` callers comes from the second argument (`"warning"` records a WARNING instead of a FAILURE).
- The log entry shape is unchanged (`src`, `msg`, `result`, `requirements`, extra args) so the HTML log,
  `expected-failures` matching by condition name and `scripts/log-fingerprint.ts` keep working.
- Inputs are explicit, typed parameters (the parsed id_token claims, the registered client), never a shared
  environment. Outputs are return values.
- Checks that are only ever used together (the standard id_token checks, the authorization-response checks)
  are grouped into one function (`idToken.validate`, `authz.checkAuthorizationResponse`) that calls them in
  upstream's order; the test calls the group.

## Sync with upstream

`upstream.lock.json` maps every Java file to `{ blob, ts, symbol }` (several Java files map to one TS file).
`pnpm sync-upstream --status` lists the Java files whose blob changed; the `// upstream:` comment and the
`symbol` find the helper to update. Message strings, severities and requirement tags stay identical to
upstream unless a deviation is deliberate and marked `// UPSTREAM:` / listed in the porting skill.

## Tooling

- pnpm (see `packageManager`), `pnpm check` (typecheck, lint, format), `pnpm test:unit` (Vitest, `src/**/*.test.ts`,
  MSW for HTTP helpers), `pnpm test` (Playwright, `tests/**/*.spec.ts`), `pnpm exec openid-conformance` (commander CLI).
- Conformance tests start their targets on free ports (`target.command` sees `PORT`, configs use `${TARGET_URL}`),
  so projects and workers run in parallel.

---
name: run-conformance
description: How to run the ported OpenID conformance test plans locally and in CI, against the bundled targets (panva oidc-provider, openid-client RP) or against an external OP/RP, how to read the report, and how to debug a failing module. Use when asked to run tests, reproduce a CI failure, or check an OP/RP implementation.
---

# Running conformance plans

## Local quick start

```bash
npm ci
npx playwright install --with-deps chromium   # once

# OP plan against the bundled panva oidc-provider (started automatically by the config)
npm run test -- --project=op-basic
# RP plan: the suite emulates the OP, the bundled openid-client RP is driven through it
npm run test -- --project=rp-basic

# Any plan/config:
CONFORMANCE_PLAN=oidcc-basic-certification-test-plan \
CONFORMANCE_VARIANT='[server_metadata=discovery][client_registration=dynamic_client]' \
CONFORMANCE_CONFIG=configs/oidc-provider/oidcc-basic.json \
npx playwright test tests/plan.spec.ts
```

Or with the CLI (same thing, nicer flags):

```bash
npx openid-conformance run --plan oidcc-basic-certification-test-plan \
  --variant client_auth_type=client_secret_basic --config ./my-config.json
npx openid-conformance list            # plans, modules, variants
npx openid-conformance run ... --module oidcc-server   # one module only
```

One Playwright test = one test module instance (`<plan> › <module>[variants]`). Each test attaches:
`log.json` (the full event log), `log.html` (rendered log, same shape as the upstream log-detail page),
screenshots of every scripted-browser page on failure, and Playwright's video/trace when enabled.

Test outcome mapping: module result PASSED/WARNING/REVIEW -> passed (WARNING/REVIEW annotated), SKIPPED ->
skipped, FAILED -> failed unless listed in the expected-failures file for the config (then it passes and is
annotated "expected failure"; an expected failure that does NOT happen fails).

## Configuration file

Same JSON as upstream (`server`, `client`, `client2`, `browser`, `alias`, `description`, ...). Extra keys used
by the port:

- `target` (optional): `{ "command": "node targets/oidc-provider/server.ts", "readyUrl": "http://localhost:3000/.well-known/openid-configuration" }`
  starts an implementation under test before the plan and stops it afterwards.
- `expectedFailures` / `expectedSkips` (optional): path to upstream-format JSON lists.
- `browser` may be a `.ts` config exporting `{ ...json, browser: async ({ page, url }) => {...} }` instead of the
  task array.

## Reading the CI summary

`conformance-report/summary.md` (also written to `$GITHUB_STEP_SUMMARY`) has one row per module: result,
failed/warned condition names with their messages, and links to the artifacts. `playwright-report/` is the full
HTML report (upload artifact). `conformance-report/results.json` is machine-readable.

## Debugging a failing module

1. Open `log.html` for the module from the report; find the first red entry. The `src` column is the condition
   class; its message and `args` tell you what was received.
2. Compare with the Java upstream condition of the same name if the failure looks like a porting error
   (`.claude/skills/java-to-ts-porting`): message text, severity and requirement must match.
3. Re-run only that module: `--module <testName>` (CLI) or `-g "<testName>"` (playwright). `--headed` opens the
   browser for the scripted-browser steps; `PWDEBUG=1` pauses.
4. For RP tests, `CONFORMANCE_KEEP_SERVER=1` keeps the emulated OP running after the module to poke it manually.
5. A genuine implementation bug in a bundled target is fixed in `targets/`; a genuine spec deviation that the
   target won't fix goes into the config's expected-failures file with a comment, exactly as upstream does.

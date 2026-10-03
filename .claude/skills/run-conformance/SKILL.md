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

One Playwright test = one test module instance (`<plan> › <module>[variants]`). Each test writes into its
`test-results/<test>/` directory (and attaches to the HTML report): `log.json` (the full event log), `log.html`
(rendered log, same shape as the upstream log-detail page), `module-report.json` (result + expected-failure
analysis), `target-output.txt` (stdout/stderr of the `target` process), screenshots of every scripted-browser
page on failure, and Playwright's video/trace when enabled. `CONFORMANCE_VERBOSE=1` streams the event log to
the console while running; `CONFORMANCE_VIDEO=off` skips video recording.

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
- `suite_target` (suite-vs-suite): `{ "module": "oidcc-client-test", "alias": "emulated-op", "variant": {...},
"config": {...} }` runs that RP test module in-process as the OP for every module of the plan and points
  `server.discoveryUrl` at it. Variant parameters left out of `suite_target.variant` are taken from the module
  under test (so `client_auth_type` follows e.g. `oidcc-server-client-secret-post`). The emulated module keeps
  answering requests after its own single flow finished (`setKeepServingAfterFinish`, not in upstream), because
  OP modules call userinfo twice, authorize twice, etc.; what it cannot emulate (single-use codes, the unusable
  keys it publishes on purpose) is listed in `configs/expected-failures/suite-vs-suite.json`.

Modules that upstream starts manually from the UI (`autoStart() == false`, i.e. `oidcc-server-rotate-keys`) are
started right away, as upstream's `run-test-plan.py` does in CI.

## Reading the CI summary

`conformance-report/summary.md` (also written to `$GITHUB_STEP_SUMMARY`) has one row per module: result,
failed/warned condition names with their messages, and links to the artifacts. `playwright-report/` is the full
HTML report (upload artifact). `conformance-report/results.json` is machine-readable.

## Checking log fidelity after framework changes

A change to `src/framework`, `src/runner`, `src/util` or `targets` must not change any log entry the ported tests
produce. `scripts/log-fingerprint.ts` reduces every `test-results/**/log.json` to one line per entry
(`[src, result, requirements, normalised msg, http/startBlock marker]`, volatile values such as test ids, ports,
random strings and timestamps masked), keyed by `<testName><variantString>` from `module-report.json`:

```bash
# before the change; Playwright empties test-results/ on every run, so fingerprint right after each one
CONFORMANCE_VIDEO=off node bin/openid-conformance.ts ci --project suite-vs-suite
node scripts/log-fingerprint.ts --out /tmp/baseline.json test-results
# after the change: the same projects/configs
CONFORMANCE_VIDEO=off node bin/openid-conformance.ts ci --project suite-vs-suite
node scripts/log-fingerprint.ts --out /tmp/current.json test-results
node scripts/log-fingerprint.ts --diff /tmp/baseline.json /tmp/current.json [--allow allowed.json] [--strict-order]
```

`--diff` prints added (`+`), removed (`-`) and changed (`~`, same src/result/requirements, different message)
entries per module, and modules found on one side only (`!!!`); any of these exits 1. `--allow` takes a JSON array
of regexes; a changed message that matches one (old or new text) is accepted. Entries that only moved (`>`) are
listed but accepted: the scripted browser and the test module log concurrently, so two runs of unchanged code
interleave some entries differently (`--strict-order` fails on moves too). The framework messages themselves are
pinned by the unit tests (`npm run test:unit`: `src/framework/*.test.ts`, `src/util/nimbus-helpers.test.ts`).

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

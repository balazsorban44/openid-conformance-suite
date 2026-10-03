---
name: run-conformance
description: How to run the ported OpenID conformance test plans locally and in CI, against the bundled targets (panva oidc-provider, openid-client RP) or against an external OP/RP, how to read the report, and how to debug a failing module. Use when asked to run tests, reproduce a CI failure, or check an OP/RP implementation.
---

# Running conformance plans

## Local quick start

```bash
npm ci
npx playwright install --with-deps chromium   # once

node bin/openid-conformance.ts projects       # the CI projects: name, plan, variant, config
# OP plan against the bundled panva oidc-provider (started automatically by the config)
node bin/openid-conformance.ts ci --project op-basic-dynamic
# RP plan: the suite emulates the OP, the bundled openid-client RP is driven through it
node bin/openid-conformance.ts ci --project rp-basic
# extra Playwright args after `--`, e.g. one module
node bin/openid-conformance.ts ci --project op-basic-dynamic -- --grep "oidcc-server\["

# Any plan/config:
node bin/openid-conformance.ts run --plan oidcc-basic-certification-test-plan \
  --variant server_metadata=discovery --variant client_registration=dynamic_client \
  --config configs/oidc-provider/oidcc-basic-dynamic.json [--module 'oidcc-server*'] [--tls] [--headed]
node bin/openid-conformance.ts list [--plans|--modules|--variants]
```

`ci` and `run` spawn `playwright test tests/plan.spec.ts` with the `CONFORMANCE_*` environment below (`ci` also
sets `CONFORMANCE_TLS=1` unless already set). `npm run test` is plain `playwright test`: it runs whatever the
environment selects (`CONFORMANCE_PROJECT=<name>`, or `CONFORMANCE_PLAN` + `CONFORMANCE_CONFIG`) and otherwise
reports a single skipped test. The Playwright project is named after `CONFORMANCE_PROJECT` (default
`conformance`), so `--project=<name>` does not select a plan. `npm run test:unit` runs the `node:test` unit tests.

One Playwright test = one test module instance (`<plan> › <module>[variants]`). Each test writes into its
`test-results/<test>/` directory (and attaches to the HTML report): `log.json` (the full event log), `log.html`
(rendered log, same shape as the upstream log-detail page), `module-report.json` (result + expected-failure
analysis), `target-output.txt` (stdout/stderr of the `target` process), screenshots of every scripted-browser
page on failure, `emulated-op-log.html` for suite-vs-suite runs, and Playwright's video/trace when enabled.

Test outcome (`src/runner/expected.ts`, a port of upstream's `run-test-plan.py` analysis): a module's test passes
when its log has no FAILURE or WARNING entry that is not in the config's expected-failures list, every listed
expected failure/warning did happen, the module was not SKIPPED unless the expected-skips list says so (then the
Playwright test is reported skipped), and it was not INTERRUPTED. Expected failures and warnings are annotated.

## Environment variables

| Variable                                                                       | Effect                                                                                  |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| `CONFORMANCE_PROJECT`                                                          | select a project from `src/runner/projects.ts` (plan, variant, config, skipped modules) |
| `CONFORMANCE_PLAN`, `CONFORMANCE_VARIANT`, `CONFORMANCE_CONFIG`                | plan name, `[k=v][k2=v2]` variant selection, config path (override the project's)       |
| `CONFORMANCE_MODULE`                                                           | only modules whose `testName` matches this glob                                         |
| `CONFORMANCE_TLS=1`, `CONFORMANCE_TLS_CERT`/`_KEY`                             | serve the suite over https (default: the bundled `configs/certs/localhost.*`)           |
| `CONFORMANCE_PORT`, `CONFORMANCE_HOST`, `CONFORMANCE_EXTERNAL_URL`             | where the suite server listens / the base URL it advertises                             |
| `CONFORMANCE_CWD`                                                              | directory the config's `target.command` runs in (the CLI sets the caller's cwd)         |
| `CONFORMANCE_MODULE_TIMEOUT` (s, 150), `CONFORMANCE_TEST_TIMEOUT` (ms, 240000) | per-module run timeout / Playwright test timeout                                        |
| `CONFORMANCE_WORKERS`                                                          | Playwright workers (default 1)                                                          |
| `CONFORMANCE_VERBOSE=1`                                                        | stream the event log to the console                                                     |
| `CONFORMANCE_TARGET_OUTPUT=1`                                                  | echo the target's stdout/stderr                                                         |
| `CONFORMANCE_KEEP_SERVER=1`                                                    | do not stop the `target` process after the plan                                         |
| `CONFORMANCE_VIDEO=off`, `CONFORMANCE_TRACE=on`                                | skip video recording / record a trace for every test                                    |
| `CONFORMANCE_LOG_FINAL_ENV=false`                                              | do not log the final environment at the end of each module                              |
| `CONFORMANCE_REPORT_DIR`, `CONFORMANCE_SUMMARY_TITLE`                          | where/with which title the summary is written (`conformance-report/`)                   |
| `CONFORMANCE_PRINT_SUMMARY=1`                                                  | print the summary to stdout (always on when `CI` is set)                                |
| `CONFORMANCE_OWNER`                                                            | the owner `sub` exposed to modules (default `ci`)                                       |

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

## CI matrix

`src/runner/projects.ts` is the matrix: each entry (name, plan, variant, config, optional `skipModules`) is one
GitHub Actions job running `node bin/openid-conformance.ts ci --project <name>`; `.github/workflows/ci.yml` reads
the names from `node bin/openid-conformance.ts projects --json`. Adding a project there adds the CI job.

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
pinned by the unit tests (`npm run test:unit`: `src/framework/*.test.ts`, `src/runner/*.test.ts`,
`src/util/{nimbus,jdk}/*.test.ts`).

## Debugging a failing module

1. Open `log.html` for the module from the report; find the first red entry. The `src` column is the condition
   class; its message and `args` tell you what was received.
2. Compare with the Java upstream condition of the same name if the failure looks like a porting error
   (`.claude/skills/java-to-ts-porting`): message text, severity and requirement must match.
3. Re-run only that module: `--module <testName>` (CLI) or `-g "<testName>"` (playwright). `--headed` opens the
   browser for the scripted-browser steps; `PWDEBUG=1` pauses.
4. `CONFORMANCE_KEEP_SERVER=1` leaves the `target` (the bundled OP or RP) running after the plan to poke it
   manually; `CONFORMANCE_TARGET_OUTPUT=1` shows its output live.
5. A genuine implementation bug in a bundled target is fixed in `targets/`; a genuine spec deviation that the
   target won't fix goes into the config's expected-failures file with a comment, exactly as upstream does.

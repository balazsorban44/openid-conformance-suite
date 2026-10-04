---
name: run-conformance
description: How to run the ported OpenID conformance test plans locally and in CI, against the bundled targets (panva oidc-provider, openid-client RP) or against an external OP/RP, how to read the report, and how to debug a failing module. Use when asked to run tests, reproduce a CI failure, or check an OP/RP implementation.
---

# Running conformance plans

## Local quick start

```bash
npm i -g pnpm      # pnpm 12 (or the standalone installer, https://pnpm.io/installation)
pnpm install --frozen-lockfile
pnpm exec playwright install --with-deps chromium   # once (firefox / webkit too for --browser firefox|webkit)

node bin/cli.ts projects       # the CI projects: name, plan, variant, config
# OP plan against the bundled panva oidc-provider (started automatically by the config)
node bin/cli.ts ci --project op-basic-dynamic
# RP plan: the suite emulates the OP, the bundled openid-client RP is driven through it
node bin/cli.ts ci --project rp-basic
# extra Playwright args after `--`, e.g. one module
node bin/cli.ts ci --project op-basic-dynamic -- --grep "oidcc-server:"
# another browser: chromium (default) | firefox | webkit | chrome-mobile
node bin/cli.ts ci --project op-session-management --browser webkit
# a plan's spec directly (tests/op/*.spec.ts, tests/rp/*.spec.ts; see .claude/skills/writing-tests)
CONFORMANCE_PROJECT=op-basic-dynamic pnpm test tests/op/basic.spec.ts

# Any plan/config:
node bin/cli.ts run --plan oidcc-basic-certification-test-plan \
  --variant server_metadata=discovery --variant client_registration=dynamic_client \
  --config configs/oidc-provider/oidcc-basic-dynamic.json [--module 'oidcc-server*'] [--browser firefox] [--tls] [--headed]
node bin/cli.ts list [--modules|--variants]   # plans (spec, variants, CI projects) [+ modules] | variant values
```

`ci` and `run` spawn `playwright test` with the `CONFORMANCE_*` environment below (`ci` also sets
`CONFORMANCE_TLS=1` unless already set). playwright.config.ts matches the selected plan's spec file (`plans` in
`src/runner/projects.ts`; every spec when no plan is selected) and turns the `CONFORMANCE_MODULE` glob into
Playwright's `grep` on the module name before the `:` of the titles. `pnpm test` is plain `playwright test`: it
runs whatever the environment selects (`CONFORMANCE_PROJECT=<name>`, or `CONFORMANCE_PLAN` +
`CONFORMANCE_CONFIG`); without a configuration the tests fail with a hint. The Playwright project is named after
`CONFORMANCE_PROJECT` (default `conformance`), suffixed with `-<browser>` when `CONFORMANCE_BROWSER` is not
chromium (`op-basic-dynamic-webkit`), so `--project=<name>` does not select a plan. `pnpm test:unit` runs
the Vitest unit tests.

One Playwright test = one test module instance (`<plan> › <module>: <behaviour>`). Each test writes into its
`test-results/<test>/` directory (and attaches to the HTML report): `log.json` (the full event log), `log.html`
(rendered log, same shape as the upstream log-detail page), `module-report.json` (result + expected-failure
analysis), `target-output.txt` (stdout/stderr of the `target` process), screenshots of every scripted-browser
page on failure, `emulated-op-log.json` / `emulated-op-log.html` for suite-vs-suite runs, and Playwright's video/trace when enabled.

Test outcome (`src/suite/expected.ts`, a port of upstream's `run-test-plan.py` analysis): a module's test passes
when its log has no FAILURE or WARNING entry that is not in the config's expected-failures list, every listed
expected failure/warning did happen, the module was not SKIPPED unless the expected-skips list says so (then the
Playwright test is reported skipped), and it was not INTERRUPTED. Expected failures and warnings are annotated.

## Environment variables

| Variable                                                        | Effect                                                                                  |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `CONFORMANCE_PROJECT`                                           | select a project from `src/runner/projects.ts` (plan, variant, config, skipped modules) |
| `CONFORMANCE_PLAN`, `CONFORMANCE_VARIANT`, `CONFORMANCE_CONFIG` | plan name, `[k=v][k2=v2]` variant selection, config path (override the project's)       |
| `CONFORMANCE_MODULE`                                            | only modules whose `testName` matches this glob                                         |
| `CONFORMANCE_BROWSER` (`ci`/`run --browser`)                    | browser the suite drives: `chromium` (default), `firefox`, `webkit`, `chrome-mobile`    |
| `CONFORMANCE_TLS=1`, `CONFORMANCE_TLS_CERT`/`_KEY`              | serve the suite over https (default: the bundled `configs/certs/localhost.*`)           |
| `CONFORMANCE_CWD`                                               | directory the config's `target.command` runs in (the CLI sets the caller's cwd)         |
| `CONFORMANCE_TEST_TIMEOUT` (ms, 240000)                         | Playwright test timeout                                                                 |
| `CONFORMANCE_WORKERS`                                           | Playwright workers (default 1)                                                          |
| `CONFORMANCE_VERBOSE=1`                                         | stream the event log to the console                                                     |
| `CONFORMANCE_TARGET_OUTPUT=1`                                   | echo the target's stdout/stderr                                                         |
| `CONFORMANCE_KEEP_SERVER=1`                                     | do not stop the `target` process after the plan                                         |
| `CONFORMANCE_VIDEO=off`, `CONFORMANCE_TRACE=on`                 | skip video recording / record a trace for every test                                    |
| `CONFORMANCE_REPORT_DIR`, `CONFORMANCE_SUMMARY_TITLE`           | where/with which title the summary is written (`conformance-report/`)                   |
| `CONFORMANCE_ARTIFACT`                                          | name of the uploaded artifact with the logs (named next to failures in the summary)     |
| `CONFORMANCE_ANNOTATIONS=1`                                     | on a GitHub runner: one `::error` per failed module (`ci` sets it)                      |

## Configuration file

Same JSON as upstream (`server`, `client`, `client2`, `browser`, `alias`, `description`, ...). Extra keys used
by the port:

- `target` (optional): `{ "command": "node targets/oidc-provider/server.ts", "url": "https://localhost:${PORT}",
"readyUrl": "${TARGET_URL}/.well-known/openid-configuration" }` starts an implementation under test before the
  plan (once per Playwright worker) and stops it afterwards. `${PORT}` is a free port the command receives as
  `PORT`; `${TARGET_URL}` (the `url`) is substituted everywhere in the configuration.
- `expectedFailures` / `expectedSkips` (optional): path to upstream-format JSON lists.
- `browser` may be a `.ts` config exporting `{ ...json, browser: async ({ page, url }) => {...} }` instead of the
  task array.
- `suite_target` (suite-vs-suite): `{ "module": "oidcc-client-test", "alias": "emulated-op", "variant": {...},
"config": {...} }` starts that RP test module's emulated OP (src/rp, tests/suite-target.ts) in-process for every
  OP test, on a server and log of its own, and points `server.discoveryUrl` at it. Variant parameters left out of
  `suite_target.variant` are taken from the module under test (so `client_auth_type` follows e.g.
  `oidcc-server-client-secret-post`). The emulated OP answers any number of requests until the test ends (OP
  modules call userinfo twice, authorize twice, etc.); what it cannot serve is in the project's `skipModules`, what
  it does differently (single-use codes, the unusable keys it publishes on purpose) is listed in
  `configs/expected-failures/suite-vs-suite.json`.

Modules that upstream starts manually from the UI (`oidcc-server-rotate-keys`) run right away, as upstream's
`run-test-plan.py` does in CI.

## Browsers

`CONFORMANCE_BROWSER` (`ci`/`run --browser <name>`) picks the browser the suite drives; playwright.config.ts turns
it into the Playwright project's `use`:

| Name            | Playwright                                                                          |
| --------------- | ----------------------------------------------------------------------------------- |
| `chromium`      | the default: the headless Chromium shell, Playwright's defaults (1280x720)          |
| `firefox`       | `devices["Desktop Firefox"]`                                                        |
| `webkit`        | `devices["Desktop Safari"]` (Safari's engine)                                       |
| `chrome-mobile` | `devices["Pixel 7"]` on Chromium: mobile viewport and user agent, touch, `isMobile` |

The browser is what the OP sees in the OP plans (authorization and login pages, logout redirects, the
check_session_iframe postMessage, front-channel logout iframes, 3rd-party-initiated login) and what the RP sees in
the RP plans whose module the suite's browser visits (session management, front-channel logout, 3rd-party-initiated
login); the other RP plans only see the RP's own HTTP client. Install the browser first (`pnpm exec playwright
install --with-deps firefox webkit`). The project name, the summary title and the CI artifact carry the browser
(`op-basic-dynamic-webkit`, `op-basic-dynamic (webkit)`, `conformance-op-basic-dynamic-webkit`); `results.json`
entries have a `browser` field. The bundled targets pass on every browser with the same expected-failure and
expected-skip lists (the suite and the targets share the `localhost` site, so WebKit's third-party storage
partitioning does not apply to the check_session_iframe or the front-channel logout iframes there; an OP on another
site may behave differently in WebKit, which is what the browser dimension is for).

## CI matrix

`src/runner/projects.ts` is the matrix: each entry (name, plan, variant, config, optional `skipModules`, optional
`browsers`) runs as one GitHub Actions job per browser, `node bin/cli.ts ci --project <name> --browser <browser>`
(job name `<project>` on chromium, `<project> (<browser>)` otherwise). `.github/workflows/ci.yml` reads the
`[{project, browser}]` pairs from `matrix()` (`node bin/cli.ts projects --json` prints them). Without `browsers` a
project runs on chromium only; the projects where the implementation under test sees the suite's browser list all
four. Adding a project there adds the CI jobs. The setup job installs and caches every browser once (one cache per
browser, keyed on the Playwright version); each matrix job restores only its own, and runs `playwright
install-deps` only when Playwright reports missing system libraries (WebKit on the ubuntu images).

## Reading the output

The console prints one line per module (`✓` passed, `?` review, `-` skipped, `~` expected failure or warning, `✗`
failed) and ends with `OK: 20 passed, 3 skipped, 1 expected failure` or `FAILED: ...` with every unexpected failure:
the condition, its message and block, and the path of the module's `log.html`. An expected failure (listed in
`configs/expected-failures`) is not a failure: it has its own count and never turns the run red.

`conformance-report/summary.md` (also appended to the job summary, `$GITHUB_STEP_SUMMARY`) is the same as a short
markdown section: unexpected failures first, then the modules that are not plain passes (expected failures, skips
and their reason, reviews), then the passed ones. `playwright-report/` is the full HTML report (upload artifact).
`conformance-report/results.json` is machine-readable (one `ModuleReport` per module with `outcome`, see the
writing-tests skill).

## Checking log fidelity after engine changes

A change to `src/suite`, `src/op`, `src/rp`, `tests/fixtures.ts` or `targets` that is not meant to change what is
checked must not change any log entry the tests produce. `scripts/log-fingerprint.ts` reduces every `test-results/**/log.json` to one line per entry
(`[src, result, requirements, normalised msg, http/startBlock marker]`, volatile values such as test ids, ports,
random strings and timestamps masked), keyed by `<testName><variantString>` from `module-report.json`:

```bash
# before the change; Playwright empties test-results/ on every run, so fingerprint right after each one
CONFORMANCE_VIDEO=off node bin/cli.ts ci --project suite-vs-suite
node scripts/log-fingerprint.ts --out /tmp/baseline.json test-results
# after the change: the same projects/configs
CONFORMANCE_VIDEO=off node bin/cli.ts ci --project suite-vs-suite
node scripts/log-fingerprint.ts --out /tmp/current.json test-results
node scripts/log-fingerprint.ts --diff /tmp/baseline.json /tmp/current.json [--allow allowed.json] [--strict-order]
```

`--diff` prints added (`+`), removed (`-`) and changed (`~`, same src/result/requirements, different message)
entries per module, and modules found on one side only (`!!!`); any of these exits 1. `--allow` takes a JSON array
of regexes; a changed message that matches one (old or new text) is accepted. Entries that only moved (`>`) are
listed but accepted: the scripted browser and the test module log concurrently, so two runs of unchanged code
interleave some entries differently (`--strict-order` fails on moves too). The engine's messages themselves are
pinned by the unit tests (`pnpm test:unit`: `src/suite/*.test.ts` including the Nimbus/JDK emulation,
`src/op/*.test.ts`, `src/rp/*.test.ts`).

## Debugging a failing module

1. Open `log.html` for the module from the report; find the first red entry. The `src` column is the upstream
   condition's name; its message and fields tell you what was received.
2. Compare with the Java upstream condition of the same name if the failure looks like a porting error
   (`grep -rn "upstream: .*/<Name>.java" src` finds the function; porting rules in `.claude/skills/writing-tests`):
   message text, severity and requirement must match.
3. Re-run only that module: `--module <testName>` (CLI) or `-g "<testName>"` (playwright). `--headed` opens the
   browser for the scripted-browser steps; `PWDEBUG=1` pauses.
4. `CONFORMANCE_KEEP_SERVER=1` leaves the `target` (the bundled OP or RP) running after the plan to poke it
   manually; `CONFORMANCE_TARGET_OUTPUT=1` shows its output live.
5. A genuine implementation bug in a bundled target is fixed in `targets/`; a genuine spec deviation that the
   target won't fix goes into the config's expected-failures file with a comment, exactly as upstream does.

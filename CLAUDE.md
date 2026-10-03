# openid-conformance-suite (TypeScript port)

TypeScript port of the OpenID Foundation conformance suite (https://gitlab.com/openid/Conformance-suite), driven
by Playwright and runnable in GitHub Actions. Currently covers the OpenID Connect Core OP and RP plans (basic,
config, dynamic client registration, RP-initiated/back-channel/front-channel logout, session management,
3rd-party-initiated login).

## Principles

- **Tests read like the test they are.** One Playwright `test()` per upstream test module, titled
  `"<module>: <what the OP/RP must do>"`, the flow visible in the test body; one spec file per plan. Read
  `.claude/skills/writing-tests` before writing or porting a test or a helper.
- **Helpers per concern.** Upstream conditions are plain functions in the file for their concern (`src/op/*.ts`,
  `src/rp/*.ts`); the engine (`src/suite`) has no OIDC knowledge. Functions, not classes with static methods;
  kebab-case file names; never a file per check.
- **Identical to upstream where it shows.** Messages, severities, requirement tags, block names and the HTTP
  exchanges are upstream's; quirks are kept and marked `UPSTREAM:`, deliberate deviations are listed in
  writing-tests.
- **Lock symbols.** Every ported function, class or test has an `upstream: <path>.java` comment;
  `upstream.lock.json` `symbols` maps each Java file to it (`pnpm lock-symbols`) so `pnpm sync-upstream` finds what
  changed upstream.
- **Least dependencies.** Runtime: `@playwright/test`, `jose`, `commander`. Dev: `typescript`, `oxlint`, `oxfmt`,
  `vitest`, `msw`, the CI targets (`oidc-provider`, `openid-client`). Prefer web and node APIs (`Response`, `URL`,
  `node:http`, `crypto`).
- **Native TS.** Node >= 24 runs the sources directly; no build step. No enums/namespaces/decorators/parameter
  properties (`erasableSyntaxOnly`). Imports carry `.ts` extensions.

## Layout

- `tests/op/*.spec.ts`, `tests/rp/*.spec.ts` - one spec per plan (`shared.ts`: modules in several plans);
  `tests/fixtures.ts` - the `op` / `client` / `configureClient` / `rp` / `variant` fixtures and the after-test
  analysis; `tests/suite-target.ts` - suite-vs-suite.
- `src/suite/` - the engine (log, conditions, http, server, browser, config, target, expected, report, wait) and
  the Java/Nimbus emulation the checks need (`jose*.ts`, `json.ts`, `errors.ts`, `uri.ts`, `bcp47.ts`,
  `json-schema.ts`, `data/`).
- `src/op/` - helpers for testing an OP (upstream client-side conditions); `src/rp/` - the emulated OP for testing
  an RP (upstream server-side conditions).
- `src/runner/projects.ts` - `plans` (plan -> title, spec, modules, variants) and `projects` (the CI matrix);
  `src/runner/list.ts` - `openid-conformance list`.
- `bin/cli.ts` - CLI (`list`, `run`, `ci`, `projects`); `action.yml` - composite GitHub Action;
  `playwright.config.ts` - selects the plan's spec from the `CONFORMANCE_*` environment.
- `scripts/` - `upstream-lock-symbols.ts`, `sync-upstream.ts`, `log-fingerprint.ts` (log fidelity diff).
- `targets/` - implementations under test for CI (panva `oidc-provider` OP, `openid-client` RP).
- `configs/` - CI test configurations, expected-failures/skips lists, the bundled TLS certificate.
- `.claude/skills/` - `writing-tests` (the design and porting rules), `run-conformance`, `sync-upstream`. Read the
  relevant one before touching the corresponding area.

## Commands

```bash
pnpm check          # typecheck + lint + format check
pnpm test:unit      # Vitest unit tests (src/**/*.test.ts, scripts/**/*.test.ts)
node bin/cli.ts ci --project <name>   # one CI project (`... projects` lists them)
node bin/cli.ts list [--modules|--variants]   # the plans
pnpm lock-symbols   # record the ported functions/tests in upstream.lock.json (`symbols`)
pnpm sync-upstream  # compare with upstream (see .claude/skills/sync-upstream)
CONFORMANCE_PROJECT=op-basic-dynamic pnpm test tests/op/basic.spec.ts   # one plan's spec against its target
```

`pnpm test` is plain `playwright test`; it runs a plan when `CONFORMANCE_PROJECT` or
`CONFORMANCE_PLAN`/`CONFORMANCE_CONFIG` select one (see `.claude/skills/run-conformance`).

Commit messages: one line summary, body explaining why. Never include model identifiers.

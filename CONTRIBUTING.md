# Contributing

## Setup

```bash
npm i -g pnpm      # pnpm 12 (or the standalone installer, https://pnpm.io/installation)
pnpm install --frozen-lockfile
pnpm exec playwright install --with-deps chromium
pnpm check        # typecheck + lint + format
pnpm test:unit    # unit tests (Vitest, src/**/*.test.ts, scripts/**/*.test.ts)
node bin/cli.ts ci --project op-basic-dynamic   # one CI project locally
```

Node.js 24+. Sources run as native TypeScript; keep to erasable syntax (no enums, namespaces, decorators,
parameter properties) and `.ts` import extensions.

## Writing and porting tests

Every upstream test module is an explicit Playwright test (`tests/op/*.spec.ts`, `tests/rp/*.spec.ts`) on helper
functions grouped by concern (`src/op`, `src/rp`, the engine in `src/suite`). Read `.claude/skills/writing-tests`
before writing a test or a check: it describes the design, how an upstream condition becomes a function, the
porting rules (Gson/Nimbus/JDK/Spring mappings) and the deliberate deviations from upstream. Messages, severities,
requirement tags and block names stay identical to upstream; every ported function or test carries an
`upstream: <path>.java` comment, and `pnpm lock-symbols` records it in `upstream.lock.json` (CI checks it).

Keeping up with upstream and adding a plan: `.claude/skills/sync-upstream`. A plan is a spec file, an entry in
`plans` and a CI project in `src/runner/projects.ts` (the CI matrix is read from it via
`node bin/cli.ts projects --json`), and a test configuration for the bundled target under `configs/`.

## Engine changes

`src/suite`, `src/op`, `src/rp`, `tests/fixtures.ts` replace upstream's Spring/MongoDB runtime and class framework.
Keep what the checks and the log rely on: the event log entry shape (`src`, `msg`, `result`, `blockId`,
`requirements`), blocks, `requestParts` for incoming requests, and the HTTP request/response log entries.

A change there or in `targets` that is not meant to change what is checked must not change any log entry the
tests produce. Before merging it, pass these gates:

1. Unit tests: `pnpm test:unit`. They pin the engine's log entries (checks, HTTP request/response entries via MSW,
   the server's requestParts), the helpers' messages and the Nimbus/JDK emulation in `src/suite`.
2. Suite-vs-suite: `node bin/cli.ts ci --project suite-vs-suite` stays green (the OP tests run against the suite's
   own emulated OP of the RP tests, so both sides are exercised).
3. Log fingerprint diff: record `scripts/log-fingerprint.ts` fingerprints of the affected projects before and after
   the change and `--diff` them; it must report no added, removed or changed entries (workflow in
   `.claude/skills/run-conformance`).

## Pull requests

CI runs typecheck/lint/format, the lock symbols check, the unit tests, and every conformance project against the
bundled targets. A change to a check must keep its message strings and severities identical to upstream unless the
PR is a sync with upstream (then the lock file moves too).

The workflows (`.github/workflows`, `.github/actions/setup`, `action.yml`) pin every action to a commit SHA with a
`# vX.Y.Z` comment; when bumping one, take the SHA of the release tag (`git ls-remote --tags` of the action's
repository, the `^{}` line for annotated tags) and update every file that uses it. A `setup` job installs the
dependencies and the Playwright headless shell once, so the matrix jobs restore the pnpm store and
`~/.cache/ms-playwright` (keyed on the Playwright version in `pnpm-lock.yaml`) instead of downloading them.

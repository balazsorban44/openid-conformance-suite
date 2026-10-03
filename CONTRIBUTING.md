# Contributing

## Setup

```bash
npm i -g pnpm      # pnpm 12 (or the standalone installer, https://pnpm.io/installation)
pnpm install --frozen-lockfile
pnpm exec playwright install --with-deps chromium
pnpm check        # typecheck + lint + format
pnpm test:unit    # unit tests (Vitest, src/**/*.test.ts)
node bin/cli.ts ci --project op-basic-dynamic   # one CI project locally
```

Node.js 24+. Sources run as native TypeScript; keep to erasable syntax (no enums, namespaces, decorators,
parameter properties) and `.ts` import extensions.

## Porting more of upstream

The suite is being rewritten from a file-by-file port of the Java classes into explicit Playwright tests with
helper functions (`tests/op/*.spec.ts`, `src/op`, `src/suite`); read `.claude/skills/writing-tests` before writing
a test or a check. The messages, severities and requirement tags stay identical to upstream either way. Before
touching `src/condition`, `src/sequence`, `src/openid`, `src/variant` or `src/util`, read the skills in
`.claude/skills/`:

1. `java-to-ts-porting` - the rulebook (read first, every time)
2. `port-conditions` / `port-test-module` - workflows
3. `sync-upstream` - how `upstream.lock.json` tracks upstream and how to add a new plan

Adding a plan in short: `pnpm sync-upstream --fetch`, `--closure net.openid.conformance.<Plan>` to list
what is missing, `--add` to register it, port, `node scripts/gen-registry.ts`, add a CI target config under
`configs/` and a project in `src/runner/projects.ts` (the CI matrix is read from it via
`node bin/cli.ts projects --json`).

## Framework changes

`src/framework/` is not 1:1 (it replaces Spring/MongoDB/UI). Keep the Java semantics that conditions and modules
rely on: the status machine and lock (`setStatus`), the event log entry shape (`src`, `msg`, `result`, `blockId`,
`requirements`), `requestParts` for incoming requests, and the HTTP request/response log entries.

A change to `src/framework`, `src/runner`, `src/util` or `targets` must not change any log entry the ported tests
produce. Before merging it, pass these gates:

1. Unit tests: `pnpm test:unit` (Vitest, `src/**/*.test.ts`, `scripts/**/*.test.ts`). They pin the engine's log
   entries (checks, HTTP request/response entries via MSW, the server's requestParts), the OP helpers' messages
   and the Nimbus/JDK emulation in `src/util/{nimbus,jdk}`.
2. Suite-vs-suite: `node bin/cli.ts ci --project suite-vs-suite` stays green (the OP tests run
   against the suite's own RP test module acting as OP, so both sides of the framework are exercised).
3. Log fingerprint diff: record `scripts/log-fingerprint.ts` fingerprints of the affected projects before and after
   the change and `--diff` them; it must report no added, removed or changed entries (workflow in
   `.claude/skills/run-conformance`).

## Pull requests

CI runs typecheck/lint/format, the unit tests, and every conformance project against the bundled targets. A
change to a condition must keep its message strings and severities identical to upstream unless the PR is a sync
with upstream (then the lock file moves too).

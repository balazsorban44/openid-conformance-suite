# Contributing

## Setup

```bash
npm ci
npx playwright install --with-deps chromium
npm run check        # typecheck + lint + format
npm run test:unit    # framework unit tests (node --test)
node bin/openid-conformance.ts ci --project op-basic-dynamic   # one CI project locally
```

Node.js 24+. Sources run as native TypeScript; keep to erasable syntax (no enums, namespaces, decorators,
parameter properties) and `.ts` import extensions.

## Porting more of upstream

The whole point of this repository is to stay a faithful, file-by-file port of the Java suite. Before touching
`src/condition`, `src/sequence`, `src/openid`, `src/variant` or `src/util`, read the skills in `.claude/skills/`:

1. `java-to-ts-porting` - the rulebook (read first, every time)
2. `port-conditions` / `port-test-module` - workflows
3. `sync-upstream` - how `upstream.lock.json` tracks upstream and how to add a new plan

Adding a plan in short: `npm run sync-upstream -- --fetch`, `--closure net.openid.conformance.<Plan>` to list
what is missing, `--add` to register it, port, `node scripts/gen-registry.ts`, add a CI target config under
`configs/` and a project in `src/runner/projects.ts` + `.github/workflows/ci.yml`.

## Framework changes

`src/framework/` is not 1:1 (it replaces Spring/MongoDB/UI). Keep the Java semantics that conditions and modules
rely on: the status machine and lock (`setStatus`), the event log entry shape (`src`, `msg`, `result`, `blockId`,
`requirements`), `requestParts` for incoming requests, and the HTTP request/response log entries.

## Pull requests

CI runs typecheck/lint/format, the unit tests, and every conformance project against the bundled targets. A
change to a condition must keep its message strings and severities identical to upstream unless the PR is a sync
with upstream (then the lock file moves too).

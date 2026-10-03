# openid-conformance-suite (TypeScript port)

TypeScript port of the OpenID Foundation conformance suite (https://gitlab.com/openid/Conformance-suite), driven
by Playwright and runnable in GitHub Actions. Currently covers the OpenID Connect Core OP and RP plans (basic,
config, dynamic client registration, RP-initiated/back-channel/front-channel logout, session management,
3rd-party-initiated login).

## Principles

- **1:1 port.** Every ported file maps to one Java class with the same name and path; messages, severities and
  spec requirement tags are identical. `upstream.lock.json` pins the upstream commit and per-file blob hashes.
- **Least dependencies.** Runtime: `@playwright/test`, `jose`, `undici`. Dev: `typescript`, `oxlint`, `oxfmt`,
  the CI targets (`oidc-provider`, `openid-client`). Prefer web APIs (`fetch`, `Response`, `URL`, `crypto.subtle`).
- **Native TS.** Node >= 24 runs the sources directly; no build step. No enums/namespaces/decorators/parameter
  properties (`erasableSyntaxOnly`). Imports carry `.ts` extensions.

## Layout

- `src/framework/` - the test framework (ported from `testmodule/`, `condition/AbstractCondition`, `sequence/`,
  `frontchannel/BrowserControl` (Playwright), `plan/`, `variant/` support, incoming HTTP server, HTTP client).
- `src/condition/{client,as,common,rs,util}/` - conditions, `src/sequence/` - sequences, `src/util/` - JOSE etc.
- `src/variant/` - variant parameter enums, `src/openid/` - test modules and plans, `src/registry.ts` - lookup.
- `src/runner/` - plan expansion, Playwright glue, reporters; `tests/plan.spec.ts` - the Playwright entry point.
- `bin/openid-conformance.ts` - CLI; `action.yml` - composite GitHub Action.
- `targets/` - implementations under test for CI (panva `oidc-provider` OP, `openid-client` RP).
- `configs/` - CI test configurations and expected-failures lists.
- `.claude/skills/` - maintenance skills: `java-to-ts-porting`, `port-conditions`, `port-test-module`,
  `sync-upstream`, `run-conformance`. Read the relevant one before touching the corresponding area.

## Commands

```bash
npm run check          # typecheck + lint + format check
npm run test           # all Playwright projects (plans x targets), see playwright.config.ts
npm run sync-upstream  # compare with upstream (see .claude/skills/sync-upstream)
```

Commit messages: one line summary, body explaining why. Never include model identifiers.

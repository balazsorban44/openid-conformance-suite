---
name: sync-upstream
description: How to find and apply changes from the upstream Java OpenID conformance suite (gitlab.com/openid/Conformance-suite) to this suite using upstream.lock.json and scripts/sync-upstream.ts. Use when asked to sync, update, bump, or diff against upstream, or when a check or test looks out of date.
---

# Syncing with upstream

The suite tracks upstream at the commit recorded in `upstream.lock.json`. Every upstream Java file that a
function, class or test ports is a `symbols` entry:

```json
{
	"upstream": { "repo": "https://gitlab.com/openid/Conformance-suite.git", "commit": "<sha>", "date": "..." },
	"symbols": {
		"src/main/java/net/openid/conformance/condition/client/ValidateIdTokenNonce.java": {
			"blob": "<git blob sha at the pinned commit>",
			"loc": 41,
			"ts": "src/op/id-token.ts",
			"symbol": "validateIdTokenNonce"
		}
	}
}
```

The entries come from the `upstream:` comments in the code (`/** upstream: condition/client/ValidateIdTokenNonce.java */`
before a function or class, `// upstream: openid/OIDCCServerTest.java` before a `test(`; a group helper lists the
conditions it calls after `with`). `pnpm lock-symbols` (`scripts/upstream-lock-symbols.ts --write`) regenerates
them; CI runs `--check`. `blob` is `git hash-object` of the Java file at the pinned commit, so a change upstream is
detected without the old checkout.

## Commands

```bash
pnpm sync-upstream --fetch                                  # partial clone/update of upstream master into .upstream/ ($UPSTREAM)
pnpm sync-upstream --status                                 # symbols whose Java source changed or was deleted since the pin (default)
pnpm sync-upstream --diff src/op/id-token.ts#validateIdTokenNonce   # the Java diff (pinned -> HEAD) of what a function ports
pnpm sync-upstream --diff src/op/id-token.ts                # the same for every symbol of a file
pnpm sync-upstream --pin                                    # after syncing: move commit + blob hashes to the upstream HEAD
```

## Workflow

1. `--fetch` then `--status`: changed and deleted symbols, as `<ts>#<symbol> <- <java>`.
2. For each changed symbol: `--diff` it, read the Java hunk, apply the same change to the function or test,
   following the porting rules in `.claude/skills/writing-tests`. Changes are usually a new log message, a new
   requirement tag, an extra check, or a changed flow in a module - port them verbatim.
3. A new condition a module now calls: add it as a function (writing-tests, "Adding a check") with its `upstream:`
   comment and call it where upstream does; a new module of a plan: a new `test()` and an entry in the plan's
   `modules` (`plans` in src/runner/projects.ts).
4. Deleted upstream: delete the function or test (and the module from `plans`).
5. `pnpm lock-symbols`, `pnpm check`, `pnpm test:unit` and the CI projects (`.claude/skills/run-conformance`).
   Fix, then `--pin`.
6. Commit the lock together with the code: "Sync with upstream <short-sha>".

## The Java/Nimbus emulation

The functions that port upstream's util classes (util/JWKUtil, JWTUtil, JWEUtil, JWAUtil, JWSUtil,
Bcp47LocaleValidation, Bcp47SubtagRegistry, validation/_) live in src/suite (jose-_.ts, uri.ts, bcp47.ts,
json-schema.ts) with `upstream: util/<Name>.java` comments, so `--status` reports them like checks. The emulation
of libraries (Nimbus JOSE+JWT, the JDK, Spring's UriComponentsBuilder, networknt's JSON schema validator) has no
upstream Java file and is not in the lock: re-check it when upstream bumps `nimbus-jose-jwt` in its `pom.xml` (the
emulated version is noted in src/suite/jose-algorithms.ts) or its JDK, and run `pnpm test:unit` after touching it.

## Adding a new plan

Read the Java plan (`openid/<Plan>.java`, `@PublishTestPlan` and `testModulesWithVariants()`) and its modules,
then follow "Plans, modules and projects" in `.claude/skills/writing-tests`: a spec file, an entry in `plans`, a
test configuration under `configs/`, a project in `projects` (the CI matrix is read from it).

## What is deliberately not ported

Upstream's Spring runtime, MongoDB persistence, UI, API controllers (`info/`, `security/`, `export/`, `sharing/`,
`statistics/`, `runner/`) and the class framework (`testmodule/`, `sequence/`, `condition/AbstractCondition`,
`variant/`, `plan/`) have no counterpart: the Playwright fixtures and src/suite replace them. Changes upstream in
those areas are evaluated by hand: if they change how a condition logs, how log entries or blocks look, how
incoming requests are parsed (`requestParts`), or how run-test-plan.py judges a result, mirror them in src/suite
or tests/fixtures.ts.

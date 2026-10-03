---
name: sync-upstream
description: How to find and apply changes from the upstream Java OpenID conformance suite (gitlab.com/openid/Conformance-suite) to this TypeScript port using upstream.lock.json and scripts/sync-upstream.ts. Use when asked to sync, update, bump, or diff against upstream, or when a ported file looks out of date.
---

# Syncing with upstream

The port tracks upstream at the commit recorded in `upstream.lock.json`:

```json
{
	"upstream": { "repo": "https://gitlab.com/openid/Conformance-suite.git", "commit": "<sha>", "date": "..." },
	"files": {
		"src/condition/client/ValidateAtHash.ts": {
			"java": "src/main/java/net/openid/conformance/condition/client/ValidateAtHash.java",
			"blob": "<git blob sha>",
			"loc": 14
		}
	}
}
```

`blob` is `git hash-object` of the Java file at the pinned commit, so a change upstream is detected without
needing the old checkout.

## Commands

```bash
npm run sync-upstream -- --fetch              # clone/update upstream master into .upstream/ (shallow)
npm run sync-upstream -- --status             # list ported files whose Java source changed since the pin (default)
npm run sync-upstream -- --diff <ts-path>     # show the Java diff (pinned -> current) for one ported file
npm run sync-upstream -- --closure <PlanClass>...   # list Java files a plan transitively needs that are not in the lock
npm run sync-upstream -- --pin                # after porting: update commit + blob hashes to the current upstream HEAD
```

## Workflow

1. `--fetch` then `--status`. Output groups files into `changed`, `deleted upstream`, `unchanged`.
2. For each changed file: `--diff` it, read the Java hunk, apply the same change to the TS file following
   `.claude/skills/java-to-ts-porting/SKILL.md`. Changes are usually a new log message, a new requirement tag,
   an extra check, or a renamed environment key - port them verbatim.
3. New Java classes referenced by changed files (a new condition a module now calls): add them to the lock with
   `--closure` (it prints the missing files) and port them (`.claude/skills/port-conditions`).
4. Deleted upstream: delete the TS file and remove it from the lock and `src/registry.ts`.
5. Run `npm run check` and the CI plans (`.claude/skills/run-conformance`). Fix, then `--pin`.
6. Commit the lock together with the code: "Sync with upstream <short-sha>".

## Adding a new plan to the port

`--closure net.openid.conformance.openid.OIDCCImplicitTestPlan` lists every Java file in the plan's transitive
dependency closure that is not yet in the lock. Add them to `files` (the script does it with `--add`), port them,
add the plan + modules to `src/registry.ts`, add a CI target config under `configs/`, add the plan to
`.github/workflows/ci.yml`.

## What is deliberately not ported

Java packages outside the lock (Spring runtime, MongoDB persistence, UI, `info/`, `security/`, `export/`,
`sharing/`, `statistics/`, API controllers) have TypeScript equivalents in `src/framework/` and `src/runner/`
that are **not** 1:1. Changes upstream in those areas are evaluated by hand: if they change how conditions are
called, how the environment or log entries look, or how incoming requests are parsed, mirror them in
`src/framework/`.

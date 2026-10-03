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
needing the old checkout. A key `<ts path>::<Name>` maps a further Java class into an existing TS file (e.g.
`src/framework/Condition.ts::PreEnvironment`); `note` marks entries that are tracked but not ported (`"not
ported: ..."`, `"dropped"`).

## Commands

```bash
npm run sync-upstream -- --fetch              # partial clone/update of upstream master into .upstream/ ($UPSTREAM)
npm run sync-upstream -- --status             # list ported files whose Java source changed since the pin (default)
npm run sync-upstream -- --diff <ts-path>     # show the Java diff (pinned -> current) for one ported file
npm run sync-upstream -- --closure <JavaFQN>...    # list Java files a plan transitively needs that are not in the lock
npm run sync-upstream -- --add <JavaFQN>...        # add those files to the lock
npm run sync-upstream -- --pin                # after porting: update commit + blob hashes to the current upstream HEAD
```

## Workflow

1. `--fetch` then `--status`. Output groups files into `changed`, `deleted upstream`, `unchanged`.
2. For each changed file: `--diff` it, read the Java hunk, apply the same change to the TS file following
   `.claude/skills/java-to-ts-porting/SKILL.md`. Changes are usually a new log message, a new requirement tag,
   an extra check, or a renamed environment key - port them verbatim.
3. New Java classes referenced by changed files (a new condition a module now calls): list them with
   `--closure`, add them to the lock with `--add` and port them (`.claude/skills/port-conditions`).
4. Deleted upstream: delete the TS file, remove it from the lock and re-run `node scripts/gen-registry.ts`.
5. Run `npm run check` and the CI plans (`.claude/skills/run-conformance`). Fix, then `--pin`.
6. Commit the lock together with the code: "Sync with upstream <short-sha>".

## Util classes and library emulation

`src/util/*Util.ts` and the other files in the lock are re-ported like conditions: `--diff src/util/JWKUtil.ts`,
apply the Java hunk to the TS method of the same name. The ported util files contain only upstream methods; when
the changed Java calls Nimbus JOSE+JWT or JDK API that is not emulated yet, add it to `src/util/nimbus/` or
`src/util/jdk/` (with a unit test, see `java-to-ts-porting`) and import it, rather than writing it into the util
file or a condition.

`src/util/nimbus/`, `src/util/jdk/` and `src/util/UriComponentsBuilder.ts` are **not** in the lock (there is no
upstream Java file for them), so `--status` never reports them. Re-check them when upstream bumps
`nimbus-jose-jwt` in its `pom.xml` (the emulated version is noted in `src/util/nimbus/algorithms.ts`) or its JDK,
and run `npm run test:unit` after touching them.

## Adding a new plan to the port

`--closure net.openid.conformance.openid.OIDCCImplicitTestPlan` lists every Java file in the plan's transitive
dependency closure that is not yet in the lock. Add them to `files` (the script does it with `--add`), port them,
regenerate `src/registry.ts` (`node scripts/gen-registry.ts`), add a CI target config under `configs/` and a
project to `src/runner/projects.ts` (the CI matrix is generated from it).

## What is deliberately not ported

Java packages outside the lock (Spring runtime, MongoDB persistence, UI, `info/`, `security/`, `export/`,
`sharing/`, `statistics/`, API controllers) have TypeScript equivalents in `src/framework/` and `src/runner/`
that are **not** 1:1. Changes upstream in those areas are evaluated by hand: if they change how conditions are
called, how the environment or log entries look, or how incoming requests are parsed, mirror them in
`src/framework/`. The `src/framework/*` entries in the lock (`testmodule/`, `frontchannel/`, `plan/`,
`AbstractCondition`, ...) only flag such changes; apply them by hand and run the framework fidelity checks in
`CONTRIBUTING.md`.

---
name: port-conditions
description: Step-by-step workflow for porting a batch of upstream Java condition classes (condition/client, condition/as, condition/common, condition/rs, condition/util, sequence/*) to this repo. Use when asked to port, add, or re-sync one or more conditions or sequences from the Java conformance suite.
---

# Porting a batch of conditions

Prerequisite: read `.claude/skills/java-to-ts-porting/SKILL.md` (the rulebook) first.

## Inputs

- The list of target TS paths (keys of `upstream.lock.json` `files`, e.g. `src/condition/client/ValidateAtHash.ts`).
  Each entry names the Java source (`java`) relative to the upstream checkout.
- An upstream checkout: `$UPSTREAM` if given, otherwise run `pnpm sync-upstream --fetch` which clones the
  pinned commit into `.upstream/`.

## Steps

1. For each file, read the Java source **and its superclass chain** (`extends Abstract...`). Port abstract bases
   first (they are in the batch when they are in the closure; otherwise they already exist in `src/`).
2. Check whether the condition depends on `src/util/*` helpers (JWKUtil, JWTUtil, ...) and whether those exist.
   If an upstream util method is missing, port it into the matching util file with the Java method name (never
   inline a copy). If the Java calls Nimbus or JDK API that has no equivalent yet, add it to `src/util/nimbus` /
   `src/util/jdk` with a unit test, never inside the condition (see the porting rulebook).
3. Write the TS file following the skeleton and mapping tables. Keep the Java javadoc and inline comments.
4. Before moving on, re-read the Java and TS side by side against the fidelity checklist.
5. After the batch: `pnpm exec tsc --noEmit -p tsconfig.json 2>&1 | grep '<your paths>'` must be empty for your files
   (errors in files other agents are still writing are expected: missing imports of not-yet-ported classes are
   fine ONLY if the import path matches the lock file's target path exactly). Run `pnpm exec oxfmt <files>` and
   `pnpm exec oxlint <files>`.
6. Do not commit; the orchestrator commits batches. Do not edit files outside your list except `src/util/*`
   additions (append-only, including `src/util/nimbus` / `src/util/jdk`) and brand-new helper files.

## Patterns that recur

- **Abstract validate-hash style classes** (`AbstractValidateHash`, `AbstractCheckForUnexpectedSchemaProperties`):
  port the abstract base with `protected` methods, subclasses call `super.method(env, ...)`.
- **HTTP-calling conditions** (`GetDynamicServerConfiguration`, `CallTokenEndpointAndReturnFullResponse`,
  `CallProtectedResource`, `FetchServerKeys`, `CallDynamicRegistrationEndpoint`, `Unregister...`): keep the Java
  base class (`AbstractCallEndpoint*`, `AbstractCallOAuthEndpoint`, ...); `async evaluate`. Java
  `createRestTemplate(env)` -> `this.createHttpClient(env)`; `createRestTemplate(env, false)` ->
  `this.createRestTemplate(env, false)`; the cached discovery/JWKS fetches use
  `await this.createRestTemplateWithCache(env)`. Always `await client.close()` in `finally`.
- **JOSE conditions** (`ValidateIdTokenSignature`, `SignRequestObject`, `ExtractJWT` family): `async evaluate`,
  use `src/util/JWTUtil.ts` / `JWKUtil.ts` and the Nimbus emulation in `src/util/nimbus`; the environment
  representation of a JWT is `{ value, header, claims, (jwe_header) }` exactly as
  `JWTUtil.jwtStringToJsonObjectForEnvironment` produces.
- **Sequences that inspect their units** (e.g. `RefreshTokenRequestSteps`): read the builder's `spec`
  (`requirements`, `onFail`, ...) and map units with `AbstractConditionSequence.actionToConditionClass`.
- **Conditions with `ENV_KEY` constants**: `static readonly ENV_KEY = "..."`.
- **`@PreEnvironment` on an abstract class** whose subclasses do not override `evaluate`: declare `static pre` on
  the base; subclasses inherit it.
- **Subclasses overriding `evaluate` with their own annotations**: declare `static override pre` on the subclass.
- **`skipIfMissing` inside sequences**: not available on sequences; Java uses the builder - do the same.
- **Time**: `Instant.now()` -> `Date.now()` (ms) or `Math.floor(Date.now()/1000)` (s). Clock-skew constants keep
  the Java names and values.

## Verifying a port quickly

Write a scratch script (do not commit) in the scratchpad, importing the repo by absolute path:

```ts
import { Environment, TestInstanceEventLog, ConditionResult } from "<repo>/src/framework/index.ts";
import { CheckStateInAuthorizationResponse } from "<repo>/src/condition/client/CheckStateInAuthorizationResponse.ts";
const env = new Environment();
env.putString("state", "abc");
env.putObject("authorization_endpoint_response", { state: "abc" });
const log = new TestInstanceEventLog("t1", (e) => console.log(e));
const c = new CheckStateInAuthorizationResponse();
c.setProperties("t1", log, ConditionResult.FAILURE, []);
await c.execute(env);
```

Run with `node scratch.ts` (Node 24 strips types natively). For anything worth keeping, write a Vitest file
next to the code instead (`pnpm test:unit` runs `src/**/*.test.ts`).

---
name: port-conditions
description: Step-by-step workflow for porting a batch of upstream Java condition classes (condition/client, condition/as, condition/common, condition/rs, condition/util, sequence/*) to this repo. Use when asked to port, add, or re-sync one or more conditions or sequences from the Java conformance suite.
---

# Porting a batch of conditions

Prerequisite: read `.claude/skills/java-to-ts-porting/SKILL.md` (the rulebook) first.

## Inputs

- The list of target TS paths (keys of `upstream.lock.json` `files`, e.g. `src/condition/client/ValidateAtHash.ts`).
  Each entry names the Java source (`java`) relative to the upstream checkout.
- An upstream checkout: `$UPSTREAM` if given, otherwise run `npm run sync-upstream -- --fetch` which clones the
  pinned commit into `.upstream/`.

## Steps

1. For each file, read the Java source **and its superclass chain** (`extends Abstract...`). Port abstract bases
   first (they are in the batch when they are in the closure; otherwise they already exist in `src/`).
2. Check whether the condition depends on `src/util/*` helpers (JWKUtil, JWTUtil, ...) and whether those exist.
   If a helper is missing, add it to the matching util file with the Java method name (never inline a copy).
3. Write the TS file following the skeleton and mapping tables. Keep the Java javadoc and inline comments.
4. Before moving on, re-read the Java and TS side by side against the fidelity checklist.
5. After the batch: `npx tsc --noEmit -p tsconfig.json 2>&1 | grep '<your paths>'` must be empty for your files
   (errors in files other agents are still writing are expected: missing imports of not-yet-ported classes are
   fine ONLY if the import path matches the lock file's target path exactly). Run `npx oxfmt <files>` and
   `npx oxlint <files>`.
6. Do not commit; the orchestrator commits batches. Do not edit files outside your list except `src/util/*`
   additions (append-only) and brand-new helper files.

## Patterns that recur

- **Abstract validate-hash style classes** (`AbstractValidateHash`, `AbstractCheckForUnexpectedSchemaProperties`):
  port the abstract base with `protected` methods, subclasses call `super.method(env, ...)`.
- **HTTP-calling conditions** (`GetDynamicServerConfiguration`, `CallTokenEndpointAndReturnFullResponse`,
  `CallProtectedResource`, `FetchServerKeys`, `CallDynamicRegistrationEndpoint`, `Unregister...`): extend the
  ported `AbstractCallEndpoint` family; use `this.createHttpClient(env)`; `async evaluate`.
- **JOSE conditions** (`ValidateIdTokenSignature`, `SignRequestObject`, `ExtractJWT` family): `async evaluate`,
  use `src/util/JWTUtil.ts` / `JWKUtil.ts`; the environment representation of a JWT is
  `{ value, header, claims, (jwe_header) }` exactly as `JWTUtil.jwtStringToJsonObjectForEnvironment` produces.
- **Conditions with `ENV_KEY` constants**: `static readonly ENV_KEY = "..."`.
- **`@PreEnvironment` on an abstract class** whose subclasses do not override `evaluate`: declare `static pre` on
  the base; subclasses inherit it.
- **Subclasses overriding `evaluate` with their own annotations**: declare `static override pre` on the subclass.
- **`skipIfMissing` inside sequences**: not available on sequences; Java uses the builder - do the same.
- **Time**: `Instant.now()` -> `Date.now()` (ms) or `Math.floor(Date.now()/1000)` (s). Clock-skew constants keep
  the Java names and values.

## Verifying a port quickly

Write a scratch script (do not commit) under `/tmp` or the scratchpad:

```ts
import { Environment, TestInstanceEventLog, ConditionResult } from "./src/framework/index.ts";
import { CheckStateInAuthorizationResponse } from "./src/condition/client/CheckStateInAuthorizationResponse.ts";
const env = new Environment();
env.putString("state", "abc");
env.putObject("authorization_endpoint_response", { state: "abc" });
const log = new TestInstanceEventLog("t1", (e) => console.log(e));
const c = new CheckStateInAuthorizationResponse();
c.setProperties("t1", log, ConditionResult.FAILURE, []);
await c.execute(env);
```

Run with `node scratch.ts` (Node 24 strips types natively).

# openid-conformance-suite

[![CI](https://github.com/balazsorban44/openid-conformance-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/balazsorban44/openid-conformance-suite/actions/workflows/ci.yml)

A TypeScript port of the [OpenID Foundation conformance suite](https://gitlab.com/openid/Conformance-suite),
driven by [Playwright](https://playwright.dev) and built to run in GitHub Actions. Point it at your OpenID
Provider / OAuth 2.0 authorization server or at your Relying Party / client and get the same checks, the same
log messages and the same spec references as the official suite, as a CI job with a readable summary.

Currently ported: the **OpenID Connect Core** OP and RP plans (basic, config, dynamic client registration,
RP-initiated / back-channel / front-channel logout, session management and 3rd-party-initiated login).
FAPI and other families are not ported yet; the structure makes adding them a matter of porting more files
(see [Maintaining](#maintaining)).

## Test your OP in GitHub Actions

```yaml
# .github/workflows/conformance.yml
on: [push, pull_request]
jobs:
  oidc-conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start my OP # anything that makes your OP reachable from the job
        run: npm start & # (or use `target` in the config file, see below)
      - uses: balazsorban44/openid-conformance-suite@main
        with:
          plan: oidcc-basic-certification-test-plan
          variant: "[server_metadata=discovery][client_registration=dynamic_client]"
          config: ./conformance/my-op.json
```

The job summary shows one row per test module with the failing conditions and their messages; the uploaded
artifact contains the Playwright HTML report with the full event log (`log.html`, the same information as the
official suite's log page), screenshots and videos of the scripted browser, and `conformance-report/results.json`
for tooling.

`my-op.json` is the same configuration format as the official suite:

```json
{
	"alias": "my-op",
	"server": { "discoveryUrl": "http://localhost:3000/.well-known/openid-configuration" },
	"client": { "client_name": "first-client" },
	"client2": { "client_name": "second-client" },
	"browser": [
		{
			"match": "http://localhost:3000/auth*",
			"tasks": [
				{
					"task": "Login",
					"optional": true,
					"match": "http://localhost:3000/interaction*",
					"commands": [
						["text", "name", "login", "user", "optional"],
						["text", "name", "password", "secret", "optional"],
						["click", "class", "login-submit"]
					]
				},
				{ "task": "Verify Complete", "match": "*/callback*", "commands": [["wait", "id", "submission_complete", 10]] }
			]
		}
	],
	"target": {
		"command": "node ./start-my-op.js",
		"readyUrl": "http://localhost:3000/.well-known/openid-configuration"
	}
}
```

- `browser` automates your login/consent pages exactly like the official suite (`click`, `text`, `wait`,
  `wait-element-visible`, `wait-element-invisible`; selectors `id`, `name`, `css`, `xpath`, `class`). If that is
  not expressive enough, use a `.ts` config and export a Playwright function instead:

  ```ts
  export default {
  	alias: "my-op",
  	server: { discoveryUrl: "http://localhost:3000/.well-known/openid-configuration" },
  	client: { client_name: "first-client" },
  	browser: async ({ page, url }) => {
  		await page.getByLabel("Username").fill("user");
  		await page.getByLabel("Password").fill("secret");
  		await page.getByRole("button", { name: "Sign in" }).click();
  		await page.waitForURL("**/callback*");
  	},
  };
  ```

- `target` (optional) starts your implementation before the plan and stops it afterwards; `command` runs in the
  directory you invoke the CLI/action from (`cwd` and `env` are optional). Leave it out if your OP is already
  running or hosted elsewhere.
- `expectedFailures` / `expectedSkips` (optional) point at JSON lists in the official suite's
  `expected-failures-*.json` format for known deviations you want to tolerate.

## Test your RP in GitHub Actions

For RP plans the suite emulates an OP and your RP must be driven through it, once per test module:

```json
{
	"alias": "my-rp",
	"client": { "client_id": "my-rp", "client_secret": "..." },
	"target": { "command": "node ./start-my-rp.js", "readyUrl": "http://localhost:4000/ready" },
	"client_driver": { "startUrl": "http://localhost:4000/start" }
}
```

The runner calls `GET {startUrl}?issuer=<emulated OP url>&module=<test name>&variant=<json>&...` and your RP must
perform the login against that issuer and respond once it is done; see
[`targets/openid-client-rp/README.md`](targets/openid-client-rp/README.md) for the exact contract and a reference
implementation built on [`openid-client`](https://github.com/panva/openid-client).

## CLI

```bash
npm install -D @balazsorban44/openid-conformance-suite
npx playwright install --with-deps chromium

npx openid-conformance list                        # plans, their variants
npx openid-conformance run --plan oidcc-basic-certification-test-plan \
   --variant server_metadata=discovery --variant client_registration=static_client \
   --config ./conformance/my-op.json [--module 'oidcc-server*'] [--headed]
```

Node.js 24 or newer; no build step (native TypeScript).

## What is in the box

|                                                  |                                                                                                                               |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `src/condition/`, `src/sequence/`, `src/openid/` | 1:1 ports of the Java conditions, sequences, test modules and plans                                                           |
| `src/framework/`                                 | the test framework (environment, condition runner, status machine, event log, HTTP client/server, Playwright browser control) |
| `targets/`                                       | implementations under test used by this repo's CI: panva's `oidc-provider` and an `openid-client` RP                          |
| `configs/`                                       | the CI test configurations and expected-failure lists                                                                         |
| `tests/plan.spec.ts`                             | the Playwright entry point                                                                                                    |
| `action.yml`                                     | the composite GitHub Action                                                                                                   |

CI runs every OP plan against `oidc-provider`, every RP plan against the `openid-client` RP, and the OP plan
against the suite's own emulated OP (suite-vs-suite), on every push to `main` and every pull request.

## Maintaining

Everything is ported 1:1 from upstream at the commit pinned in `upstream.lock.json`, which also records the
blob hash of every ported Java file. `npm run sync-upstream` reports which ported files changed upstream, shows
the Java diffs, and finds the files a new plan needs. The porting rules live in `.claude/skills/` and are written
for both humans and coding agents:

- `java-to-ts-porting` - the rulebook (framework API equivalents, Gson/Nimbus/Spring mappings, fidelity checklist)
- `port-conditions`, `port-test-module` - workflows for conditions/sequences and modules/plans/variants
- `sync-upstream` - keeping up with upstream
- `run-conformance` - running and debugging plans

## License

MIT, same as upstream. This is a derivative work of the OpenID Foundation conformance suite; it is not
affiliated with or endorsed by the OpenID Foundation and does not grant certification.

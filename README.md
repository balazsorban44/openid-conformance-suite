# openid-conformance-suite

[![CI](https://github.com/balazsorban44/openid-conformance-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/balazsorban44/openid-conformance-suite/actions/workflows/ci.yml)

The [OpenID Foundation conformance suite](https://gitlab.com/openid/Conformance-suite) in TypeScript, driven by
[Playwright](https://playwright.dev), made for CI. Point it at your OpenID Provider or Relying Party and get the
official suite's checks, messages and spec references as a job with a readable summary.

Ported so far: the **OpenID Connect Core** OP and RP plans (basic, config, dynamic registration, RP-initiated,
back-channel and front-channel logout, session management, 3rd-party-initiated login).

## Test your OP in GitHub Actions

```yaml
# .github/workflows/conformance.yml
on: [push, pull_request]
jobs:
  oidc-conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - run: npm start & # or use `target` in the config file
      - uses: balazsorban44/openid-conformance-suite@main
        with:
          plan: oidcc-basic-certification-test-plan
          variant: "[server_metadata=discovery][client_registration=dynamic_client]"
          config: ./conformance/my-op.json
```

The job summary lists unexpected failures first (condition, message, log), then skipped, review and expected-failure
modules. On failure the artifact has the full event log (`log.html`), screenshots, videos and `results.json`.

The action installs and caches the browser it drives. `browser: firefox`, `webkit` or `chrome-mobile` runs the
plan in another browser.

`my-op.json` uses the official suite's configuration format:

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

- `browser` scripts your login and consent pages like the official suite (`click`, `text`, `wait`,
  `wait-element-visible`, `wait-element-invisible`; selectors `id`, `name`, `css`, `xpath`, `class`). A `.ts`
  config can export a Playwright function instead:

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

- `target` (optional) starts your implementation before the plan and stops it afterwards. With
  `"url": "http://localhost:${PORT}"` the suite picks a free port, passes it as `PORT` and replaces `${TARGET_URL}`
  in the configuration.
- `expectedFailures` / `expectedSkips` (optional) point at lists in the official suite's `expected-failures-*.json`
  format.

## Test your RP in GitHub Actions

The suite emulates an OP and drives your RP through it once per test module:

```json
{
	"alias": "my-rp",
	"client": { "client_id": "my-rp", "client_secret": "..." },
	"target": { "command": "node ./start-my-rp.js", "readyUrl": "http://localhost:4000/ready" },
	"client_driver": { "startUrl": "http://localhost:4000/start" }
}
```

The suite calls `GET {startUrl}?issuer=<emulated OP>&module=<test name>&variant=<json>` and your RP logs in against
that issuer. [`targets/openid-client-rp/README.md`](targets/openid-client-rp/README.md) has the contract and a
reference implementation.

## CLI

```bash
pnpm add -D @balazsorban44/openid-conformance-suite
pnpm exec playwright install --with-deps chromium

pnpm exec openid-conformance list [--modules]
pnpm exec openid-conformance run --plan oidcc-basic-certification-test-plan \
   --variant server_metadata=discovery --variant client_registration=static_client \
   --config ./conformance/my-op.json [--module 'oidcc-server*'] [--browser webkit] [--headed]
```

Node.js 24 or newer. `--browser` is `chromium` (default), `firefox`, `webkit` or `chrome-mobile`.

## Web UI

A checkout has a local web UI like the official suite's: plans and projects with every module's latest result, a
dialog to start a run, live progress, and each module's log with its conditions, HTTP exchanges and screenshots.
`pnpm install && pnpm ui` serves it on http://127.0.0.1:3000; see [`ui/README.md`](ui/README.md), which also has
the Vercel settings for a hosted read-only copy.

[![The UI's overview](ui/docs/overview-light.png)](ui/README.md)

## What is in the box

|                                              |                                                                                          |
| -------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `tests/op/*.spec.ts`, `tests/rp/*.spec.ts`   | one Playwright test per upstream test module, one spec file per plan                     |
| `tests/fixtures.ts`, `tests/suite-target.ts` | the `op` / `client` / `rp` fixtures, the after-test analysis, suite-vs-suite             |
| `src/suite/`                                 | the engine: event log, checks, HTTP, scripted browser, config, report                    |
| `src/op/`, `src/rp/`                         | upstream's conditions as functions: testing an OP, and the emulated OP for RP tests      |
| `src/runner/`, `bin/cli.ts`                  | the plans, the CI projects and the `openid-conformance` CLI                              |
| `ui/`                                        | the web UI                                                                               |
| `scripts/`                                   | upstream sync, lock symbols, log fidelity diff                                           |
| `targets/`                                   | the implementations this repo's CI tests: panva's `oidc-provider`, an `openid-client` RP |
| `configs/`                                   | the CI configurations and expected-failure lists                                         |
| `action.yml`                                 | the composite GitHub Action                                                              |

CI runs every OP plan against `oidc-provider`, every RP plan against the `openid-client` RP and the OP basic plan
against the suite's own emulated OP, on Chromium, and the browser-driven projects on Firefox, WebKit and Chrome
mobile too.

## Maintaining

`upstream.lock.json` pins the upstream commit and maps every ported Java file to the function or test that ports it
(from the `upstream:` comments). `pnpm sync-upstream` shows what changed upstream. The rules are in `.claude/skills/`:
`writing-tests` (design and porting rules), `sync-upstream`, `run-conformance`.

## License

MIT, like upstream. A derivative work of the OpenID Foundation conformance suite, not affiliated with or endorsed
by the OpenID Foundation; it does not grant certification.

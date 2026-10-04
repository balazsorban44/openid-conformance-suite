# openid-conformance-suite

[![CI](https://github.com/balazsorban44/openid-conformance-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/balazsorban44/openid-conformance-suite/actions/workflows/ci.yml)

The [OpenID Foundation conformance suite](https://gitlab.com/openid/Conformance-suite) in TypeScript, driven by
[Playwright](https://playwright.dev), made for CI. Same checks, messages and spec references as the official suite.

- [x] OpenID Connect Core, OpenID Provider
  - [x] basic, config, dynamic client registration
  - [x] RP-initiated, back-channel and front-channel logout, session management, 3rd-party-initiated login
  - [x] implicit and hybrid flows, form_post response mode
- [x] OpenID Connect Core, Relying Party
  - [x] basic, config, dynamic client registration
  - [x] implicit and hybrid flows, form_post response mode
  - [x] RP-initiated, back-channel and front-channel logout, session management, 3rd-party-initiated login,
        refresh token
- [ ] FAPI 2 Security Profile and Message Signing, OpenID Provider (in progress: the discovery, happy flow,
      refresh token, PAR / PKCE, client assertion, DPoP binding, code binding and signed request object / JARM
      modules; client_auth_type=private_key_jwt and sender_constrain=dpop only, mTLS is not covered)
- [ ] FAPI 2 Security Profile and Message Signing, Relying Party (in progress: the happy path, discovery, id_token,
      authorization response, token endpoint, DPoP nonce and JARM modules; client_auth_type=private_key_jwt and
      sender_constrain=dpop only, mTLS is not covered; the ecosystem-only refresh token module and grant
      management are not ported)
- [ ] FAPI 1 Advanced, FAPI-CIBA
- [ ] OpenID Federation, Shared Signals Framework, OpenID4VC issuer / wallet / verifier, eKYC, AuthZEN

## OP

```yaml
# .github/workflows/conformance.yml
on: [push, pull_request]
jobs:
  oidc-conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - run: npm start & # or `target` in the config
      - uses: balazsorban44/openid-conformance-suite@main
        with:
          plan: oidcc-basic-certification-test-plan
          variant: "[server_metadata=discovery][client_registration=dynamic_client]"
          config: ./conformance/my-op.json
```

The job summary lists unexpected failures first, then skipped, review and expected-failure modules. On failure the
artifact has the event log (`log.html`), screenshots, videos and `results.json`. `browser: firefox`, `webkit` or
`chrome-mobile` runs the plan in another browser.

`my-op.json` is the official suite's configuration format:

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

- `browser`: the official suite's scripted login (`click`, `text`, `wait`, `wait-element-visible`,
  `wait-element-invisible`; selectors `id`, `name`, `css`, `xpath`, `class`). A `.ts` config can export a
  Playwright function `browser: async ({ page, url }) => { ... }` instead.
- `target` (optional): starts your implementation before the plan. `"url": "http://localhost:${PORT}"` gets a free
  port, passed as `PORT` and as `${TARGET_URL}` in the configuration.
- `expectedFailures`, `expectedSkips` (optional): lists in the official suite's `expected-failures-*.json` format.

## RP

```json
{
	"alias": "my-rp",
	"client": { "client_id": "my-rp", "client_secret": "..." },
	"target": { "command": "node ./start-my-rp.js", "readyUrl": "http://localhost:4000/ready" },
	"client_driver": { "startUrl": "http://localhost:4000/start" }
}
```

The suite emulates an OP and calls `GET {startUrl}?issuer=<emulated OP>&module=<test name>&variant=<json>` once
per module; your RP logs in against that issuer. Contract and reference implementation:
[`targets/openid-client-rp/README.md`](targets/openid-client-rp/README.md).

## CLI

```bash
pnpm add -D @balazsorban44/openid-conformance-suite
pnpm exec playwright install --with-deps chromium

pnpm exec openid-conformance list [--modules]
pnpm exec openid-conformance run --plan oidcc-basic-certification-test-plan \
   --variant server_metadata=discovery --variant client_registration=static_client \
   --config ./conformance/my-op.json [--module 'oidcc-server*'] [--browser webkit] [--headed]
```

Node.js 24 or newer.

## Web UI

`pnpm install && pnpm ui` in a checkout: plans and projects with every module's latest result, runs with live
progress, each module's log with its conditions, HTTP exchanges and screenshots. See
[`ui/README.md`](ui/README.md).

[![The UI's overview](ui/docs/overview-light.png)](ui/README.md)

## Maintaining

`upstream.lock.json` pins the upstream commit and maps every ported Java file to its function or test. A weekly
job opens a "Sync with upstream" pull request with the diffs to port. Rules: `.claude/skills/`.

## License

MIT. A derivative work of the OpenID Foundation conformance suite; not affiliated with or endorsed by the OpenID
Foundation, and no certification.

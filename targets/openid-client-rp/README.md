# openid-client RP target

The Relying Party under test for the RP plans (`oidcc-client-*`). It is built on panva's
[openid-client](https://github.com/panva/openid-client) v6 and replaces upstream's
[sample-openid-client-nodejs](https://gitlab.com/openid/sample-openid-client-nodejs) (openid-client v3).

```bash
node targets/openid-client-rp/server.ts      # prints "ready" once listening on http://localhost:4000 (PORT)
```

`PORT` (http, default 4000) and `RP_HTTPS_PORT` (https, default 4443, `0` disables) choose the listeners. The
configs in `configs/openid-client-rp/` let the suite pick free ports (src/suite/target.ts): `"url":
"http://localhost:${PORT}"`, `"env": { "RP_HTTPS_PORT": "${PORT_HTTPS}" }`, and use `${TARGET_URL}` and
`${PORT_HTTPS}` wherever the RP's URLs appear (readyUrl, `client_driver.startUrl`, static `redirect_uri`, browser
matches), so several projects and workers can run the RP at the same time.

## How upstream drives its RP, and what this target does instead

Upstream `scripts/run-test-plan.py` creates the RP test module, waits for it to reach `WAITING`, then for
`{sample-openid-client-nodejs[...]}` plans runs `npm run client` in the sample client checkout with:

| env var                    | value                                                                                                                           |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `ISSUER`                   | `$CONFORMANCE_SERVER` + `test/a/<alias>/` (the suite's emulated OP, trailing slash)                                             |
| `MODULE_NAME`              | the test module name, e.g. `oidcc-client-test-invalid-iss`                                                                      |
| `VARIANT`                  | JSON of the plan + module variant (`client_auth_type`, `response_type`, `response_mode`, `request_type`, `client_registration`) |
| `CLIENT_METADATA_DEFAULTS` | JSON of the `[name=value]` bracket options of the plan line, e.g. `{"id_token_signed_response_alg":"ES256"}`                    |
| others                     | the `(NAME=value)` options (e.g. `CLIENT_CERT`), `NODE_TLS_REJECT_UNAUTHORIZED=0`                                               |

The script runs `modules/<MODULE_NAME>.js` (discover, register, authorize with a headless HTTP GET to the
authorization endpoint, read the `Location`/form_post response, token, userinfo), exits, and run-test-plan.py then
waits for the module to be `FINISHED`.

This target keeps exactly those inputs but is a long running HTTP server driven with one request per module, and it
receives the authorization responses on real callback endpoints through a real user agent (Playwright chromium), so
logout, session management and third party initiated login modules work too.

## Driver contract

1. The suite starts the process from the config's `target.command` and waits until `target.readyUrl`
   (`${TARGET_URL}/ready`) answers 200.
2. For every RP test module, once the test has started the suite's emulated OP (`rp.start()`), it calls
   (`rp.driveClient()`, src/rp/rp.ts)

   ```
   GET {client_driver.startUrl}?issuer=<url>&module=<testName>&variant=<json>&client_metadata_defaults=<json>&alias=<alias>
       [&client_id=<id>&client_secret=<secret>&jwks=<private jwks json>]
   ```

   | parameter                            | meaning                                                                                                                                                                                                                               |
   | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | `issuer`                             | the emulated OP, e.g. `http://localhost:PORT/test/a/<alias>/` (same as upstream's `ISSUER`)                                                                                                                                           |
   | `module`                             | test module name (upstream `MODULE_NAME`)                                                                                                                                                                                             |
   | `variant`                            | JSON object variant name -> value (upstream `VARIANT`), e.g. `{"client_auth_type":"client_secret_basic","response_type":"code","response_mode":"default","request_type":"plain_http_request","client_registration":"dynamic_client"}` |
   | `client_metadata_defaults`           | JSON object of extra registration metadata (upstream `CLIENT_METADATA_DEFAULTS`); configs may carry it as `client_metadata_defaults`                                                                                                  |
   | `alias`                              | the suite alias (only used to build the webfinger `acct:` resource)                                                                                                                                                                   |
   | `client_id`, `client_secret`, `jwks` | static client (`client_registration=static_client`), taken from the test config's `client`; defaults `openid-client-rp` / `rp-secret-0123456789abcdefghij` (or `RP_STATIC_CLIENT_ID` / `RP_STATIC_CLIENT_SECRET`)                     |

3. The request blocks until the RP has run the whole flow for that module (or gave up) and answers 200 with

   ```json
   {
   	"ok": true,
   	"module": "oidcc-client-test",
   	"outcome": "signed in",
   	"error": "...",
   	"steps": ["discovered ...", "..."]
   }
   ```

   `ok` says whether the RP behaved as the module expects - like the upstream sample client's `assert.doesNotReject`
   / `assert.rejects`: for negative modules (invalid signature, wrong `iss`, ...) `ok` is true when the RP rejected
   the response, and `error` carries the rejection. `steps` is a human readable log for the report. A malformed
   request gets 400.

4. Meanwhile the test follows the requests the RP sends to the emulated OP; the answer tells it that no further
   requests will come. The module result in the suite is authoritative; `ok` is informational.

Static RP configs must register the RP's endpoints at the suite: `client.redirect_uri` `${TARGET_URL}/cb`
(and for logout plans `post_logout_redirect_uri` `${TARGET_URL}/logged-out`, `backchannel_logout_uri`
`${TARGET_URL}/backchannel-logout`, `frontchannel_logout_uri` `${TARGET_URL}/frontchannel-logout`).

## RP endpoints

| endpoint                                             | purpose                                                                                                                                                                                                                               |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /ready`                                         | readiness probe                                                                                                                                                                                                                       |
| `GET /start`                                         | driver entry point (above)                                                                                                                                                                                                            |
| `GET /jwks`                                          | the RP's public keys (also sent inline as `jwks` at registration when needed)                                                                                                                                                         |
| `GET /login?flow=`                                   | where the RP's user agent starts; 302 to the authorization endpoint                                                                                                                                                                   |
| `GET /cb`                                            | `redirect_uri`: query responses; for fragment responses it serves a page that posts the fragment to `/cb-fragment`                                                                                                                    |
| `POST /cb`                                           | `response_mode=form_post` responses                                                                                                                                                                                                   |
| `POST /cb-fragment`                                  | fragment responses (implicit / hybrid)                                                                                                                                                                                                |
| `GET /request-object/<id>`                           | request objects passed by reference (`request_uri`)                                                                                                                                                                                   |
| `GET /logout?flow=`                                  | RP-initiated logout: 302 to `end_session_endpoint` with `id_token_hint`, `post_logout_redirect_uri`, `state`                                                                                                                          |
| `GET /logged-out`                                    | `post_logout_redirect_uri`                                                                                                                                                                                                            |
| `POST /backchannel-logout`                           | `backchannel_logout_uri`: validates the `logout_token` (signature with the OP JWKS and the ID Token alg, `iss`, `aud`, `iat`, `jti`, `events`, no `nonce`, `sub` or `sid`); 200 + `Cache-Control: no-store` on success, 400 otherwise |
| `GET /frontchannel-logout`                           | `frontchannel_logout_uri` (`iss`, `sid`): clears the session, 200 HTML                                                                                                                                                                |
| `GET /session-check?flow=&phase=`                    | session management: loads the OP's `check_session_iframe` and posts `client_id session_state` to it                                                                                                                                   |
| `GET /session-status`                                | where the session check page reports the iframe's answer                                                                                                                                                                              |
| `GET https://localhost:${PORT_HTTPS}/initiate-login` | `initiate_login_uri` (`iss`, `login_hint`, `target_link_uri`), https because the suite requires it (ValidateClientInitiateLoginUri); certificate `configs/certs/localhost.crt` (`RP_HTTPS_PORT=0` disables)                           |

## What the RP does per module

Default (any module not listed, e.g. `oidcc-client-test`, `kid-absent-single-jwks`, `mtls-endpoint-aliases`,
`userinfo-signed`, `nonce-unless-code-flow`): discovery, dynamic registration (or static client), authorization
request (always `state` and `nonce`, PKCE S256 for response types with `code`, `request`/`request_uri` per
`request_type`), callback, token request (`client_auth_type`), userinfo when an access token was issued. The suite
finishes these modules after the userinfo request (`id_token`: after the authorization + jwks requests).

| module(s)                                                                                                                                                                                                                                 | RP behaviour                                                                                                                                                                                              | expected                                                     |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `invalid-iss`, `missing-sub`, `invalid-aud`, `missing-aud`, `missing-iat`, `kid-absent-multiple-jwks`, `invalid-sig-rs256`, `nonce-invalid`, `missing-chash`, `invalid-chash`, `missing-athash`, `invalid-athash`, `userinfo-invalid-sub` | normal login                                                                                                                                                                                              | rejected (the suite waits `waitTimeoutSeconds` and finishes) |
| `invalid-sig-es256`, `invalid-sig-hs256`                                                                                                                                                                                                  | registers `id_token_signed_response_alg` ES256 / HS256                                                                                                                                                    | rejected                                                     |
| `idtoken-sig-rs256`, `idtoken-sig-none`, `client-secret-basic`                                                                                                                                                                            | registers the corresponding metadata (as the sample client)                                                                                                                                               | success                                                      |
| `form-post-error`                                                                                                                                                                                                                         | `max_age=0&prompt=none`                                                                                                                                                                                   | rejected (`login_required`)                                  |
| `scope-userinfo-claims`, `aggregated-claims`, `distributed-claims`                                                                                                                                                                        | `scope=openid email`; unpacks `_claim_sources` (JWT / calls the claims endpoint)                                                                                                                          | `email` / `address` / `credit_score` present                 |
| `userinfo-bearer-header`, `userinfo-bearer-body`                                                                                                                                                                                          | access token in the `Authorization` header / form body                                                                                                                                                    | success                                                      |
| `request-uri-signed-rs256`, `request-uri-signed-none`                                                                                                                                                                                     | `request_uri` with an RS256 / unsigned request object hosted at `/request-object/<id>`                                                                                                                    | success                                                      |
| `refresh-token`, `refresh-token-invalid-issuer`, `refresh-token-invalid-sub`                                                                                                                                                              | login without userinfo, refresh grant, then userinfo with the new token (the suite finishes after that userinfo)                                                                                          | success / rejected / rejected                                |
| `discovery-openid-config`                                                                                                                                                                                                                 | discovery only                                                                                                                                                                                            | success                                                      |
| `discovery-jwks-uri-keys`                                                                                                                                                                                                                 | discovery + jwks_uri                                                                                                                                                                                      | success                                                      |
| `discovery-webfinger-acct`, `discovery-webfinger-url`                                                                                                                                                                                     | WebFinger (`acct:<alias>.<module>@host` / `<issuer><module>`), then discovery of the returned issuer                                                                                                      | success                                                      |
| `discovery-issuer-mismatch`                                                                                                                                                                                                               | WebFinger + discovery                                                                                                                                                                                     | rejected (issuer mismatch)                                   |
| `dynamic-registration`                                                                                                                                                                                                                    | discovery + registration (suite finishes on registration)                                                                                                                                                 | success                                                      |
| `signing-key-rotation*`                                                                                                                                                                                                                   | two logins; the second with a Configuration without cached JWKS so the rotated key is fetched                                                                                                             | success                                                      |
| `3rd-party-init-login`                                                                                                                                                                                                                    | registers `initiate_login_uri`, then waits; the suite's own browser visits it with `iss`, the RP starts the authorization request from there                                                              | success                                                      |
| `rp-init-logout`, `rp-init-logout-other-state`, `rp-init-logout-no-state`, `rp-frontchannel-rpinitlogout`                                                                                                                                 | registers post logout / back- and front-channel URIs, login, `/logout` -> end_session; the suite calls the back-channel URI and/or renders the front-channel iframe page, then redirects to `/logged-out` | success                                                      |
| `rp-backchannel-rpinitlogout`                                                                                                                                                                                                             | as above; the `logout_token` must be accepted (200)                                                                                                                                                       | accepted                                                     |
| `rp-backchannel-rpinitlogout-{alg-none,no-event,with-nonce,wrong-alg,wrong-aud,wrong-event,wrong-iss}`                                                                                                                                    | as above; the `logout_token` must be rejected (400)                                                                                                                                                       | rejected                                                     |
| `rp-frontchannel-opinitlogout`                                                                                                                                                                                                            | login, then waits for the suite's browser to load `frontchannel_logout_uri`                                                                                                                               | front-channel request received                               |
| `session-management`                                                                                                                                                                                                                      | login, session check (`unchanged`), RP-initiated logout, session check (`changed`)                                                                                                                        | success                                                      |

The test modules this mirrors are in upstream `src/main/java/net/openid/conformance/openid/client/` and
`client/logout/`: `finishTestIfAllRequestsAreReceived()` in each module says which requests end it (e.g. the
logout modules need the authorization request plus the end_session request, and the back-channel request was sent
/ the front-channel iframe callback was received; session management needs `get_session_state` calls before and
after logout).

## User agent

The RP's front-channel navigation runs in Playwright's chromium (`RP_CHROMIUM_EXECUTABLE_PATH` to pick a binary).

## Known openid-client v6 limitations (candidates for `configs/expected-failures/openid-client-rp.json`)

- ID Tokens / UserInfo signed with `none`, `HS*` or `ES256K` are not supported (`idtoken-sig-none` fails).
- Symmetric JWE key management (`A*KW`, `A*GCMKW`, `dir`) and request object encryption are not supported.
- `tls_client_auth` / `self_signed_tls_client_auth` are not implemented by this target.
- `code token` / `id_token token` / `code id_token token` are not handled by openid-client itself; the target
  strips the front-channel access token, lets openid-client validate the rest and checks `at_hash` itself.

## Self test against the bundled OP

`OIDC_PROVIDER_AUTO_APPROVE=1 node targets/oidc-provider/server.ts` starts the OP without login/consent/logout
prompts; `GET /start?issuer=http://localhost:3000&module=oidcc-client-test&variant=...` then runs the RP flows
against it (including `rp-init-logout`, back-channel logout and `session-management`).

# Reference

Everything a GrantCentral project can contain and every command that runs it.
New here? Start with [Getting started](getting-started.md).

## Projects

```
grantcentral.toml               name, default_environment
environments/dev.toml           committed: variables, secret references, [client] defaults
environments/dev.local.toml     git-ignored overrides (literal secrets are fine here)
flows/**/*.toml                 one flow per file
.grantcentral/schema/*.json     JSON schemas for editor validation (`grantcentral schema --write`)
```

Files written by `init` start with a `#:schema` comment, so TOML editors
such as Taplo/Even Better TOML validate and complete them.

## Environments

```toml
[vars]                                     # {{ issuer }}, {{ client_id }}
issuer = "https://idp.example.com"
client_id = "grantcentral-dev"

[secrets]                                  # {{ secrets.client_secret }}, redacted from reports
client_secret = { env = "GC_DEV_CLIENT_SECRET" }   # CI
# client_secret = { keyring = "dev/client_secret" } # OS keychain
# client_secret = { file = "/run/secrets/cs" }      # mounted secret
# client_secret = "literal"                         # only in *.local.toml

[client]
issuer = "{{ issuer }}"
client_id = "{{ client_id }}"
client_secret = "{{ secrets.client_secret }}"
redirect_uri = "http://127.0.0.1/callback"  # no port: a free one per run (RFC 8252 §7.3)
scope = "openid profile"
```

Precedence is, from lowest to highest: flow `[vars]`, environment, `*.local.toml`, `--var key=value`.
A flow's `[client]` table overrides the environment's field by field.

| `[client]` key | Meaning |
|---|---|
| `issuer`, `client_id`, `client_secret`, `redirect_uri`, `scope` | the basics |
| `auth_method` | `none`, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`. Inferred when unset. |
| `signing_key`, `signing_alg` | JWK or PEM key for private_key_jwt, request objects and JWT bearer assertions |
| `assertion_audience` | `issuer` (default, per RFC 7523bis), `endpoint`, or a URL |
| `decryption_key` | key for encrypted ID tokens, UserInfo and introspection responses |
| `dpop`, `dpop_key`, `dpop_alg` | DPoP (RFC 9449); a key is generated per run unless `dpop_key` is set |
| `tls_cert`, `tls_key`, `ca_cert`, `insecure` | mutual TLS (RFC 8705) and trust settings |
| `endpoints` | per-endpoint overrides, e.g. `{ token_endpoint = "..." }`, for servers without discovery |
| `timeout` | HTTP timeout in seconds (default 30) |

## Flows

```toml
name = "Authorization code with PKCE"
tags = ["smoke"]

[[steps]]
type = "discover"

[[steps]]
id = "login"
type = "authorize"            # PKCE S256 by default
par = true                    # RFC 9126
request_object = "signed"     # RFC 9101 (also "encrypted", "unsigned" for negative tests)
login = "chromium"            # how the user agent is driven (see below)
login_script = [
  { fill = "#username", value = "{{ username }}" },
  { fill = "#password", value = "{{ secrets.password }}" },
  { click = "button[type=submit]" },
  { click = "#consent", optional = true },
]

[[steps]]
id = "tok"
type = "token"
assert = ["status == 200", "body.expires_in > 0", "claims.id_token.sub"]
capture = { refresh = "body.refresh_token" }

[[steps]]
name = "a reused code is rejected"
type = "token"
code = "{{ steps.login.callback.code }}"
expect = "error"
assert = ["body.error == 'invalid_grant'"]
```

Every step accepts:

- `id`: makes the result available as `steps.<id>` in later steps.
- `name`
- `when`: an expression; the step is skipped when it is false.
- `expect`: `success` (the default), `error` for negative tests, or `any`.
- `assert`: a list of expressions.
- `capture`: variables to set from expressions over the result.

| `type` | Does | Notable options |
|---|---|---|
| `discover` | RFC 8414 / OIDC discovery and the JWKS | `issuer`, `url`, `well_known = auto\|oauth\|openid` |
| `discover_resource` | RFC 9728 protected resource metadata | `resource`, `url` |
| `audit` | metadata against RFC 9700, 9207, 10017, 8252, ... | `profile = confidential\|browser\|native` |
| `register` / `manage_client` | RFC 7591 / RFC 7592 | `metadata`, `initial_access_token`, `action = read\|update\|delete` |
| `authorize` | front-channel request and response | `response_type`, `response_mode`, `pkce`, `par`, `request_object`, `duplicate_params`, `request_uri`, `authorization_details`, `resource`, `acr_values`, `max_age`, `prompt`, `claims`, `dpop_jkt`, `params`, `remove`, `login`, `login_script` |
| `token` | any grant | `grant_type` (`authorization_code`, `refresh_token`, `client_credentials`, `password`, `token_exchange`, `jwt_bearer`, `saml2_bearer`, `device_code`, or any URI), grant parameters, `assertion_claims`, `validate_access_token`, `params`, `remove` |
| `device` | RFC 8628 with polling | `scope`, `poll`, `login`, `login_script` (`{{ session.user_code }}` is available) |
| `introspect` | RFC 7662, JWT responses per RFC 9701 | `token`, `token_type_hint`, `jwt_response` |
| `revoke` | RFC 7009 | `token`, `token_type_hint` |
| `userinfo` | OIDC UserInfo, JSON or JWT | `method`, `access_token` |
| `request` | call a protected resource | `url`, `method`, `headers`, `json`/`form`/`body`, `auth = auto\|bearer\|bearer_body\|bearer_query\|dpop\|none` |
| `validate_jwt` | ID token, RFC 9068 access token, or generic JWT | `token`, `profile`, `audience` |
| `wait` | sleep | `seconds` |

`params` adds or replaces request parameters and `remove` drops default ones.
Together they make it easy to send malformed requests on purpose.

**Templates and expressions** use minijinja. Strings are templates
(`"{{ issuer }}/x"`). `assert`, `capture` and `when` take expressions such as
`'openid' in body.scope`. Both can use:

- your variables at the top level;
- `vars`, `secrets` and `client`;
- `session`: the protocol state, e.g. `session.access_token`, `session.dpop_jkt`, `session.nonce`, `session.metadata.*`;
- `steps.<id>`: results of earlier steps;
- in `assert` and `capture` only, the step's own result: `status`, `headers`, `body`, `claims`, `callback`, `challenge`, `error`, `checks`, ...

Filters: `jwt` (decode), `b64url`, `b64url_decode`, `sha256`. Functions: `now()` and `random(n)`.
A string that is exactly one `{{ expr }}` and evaluates to an object or array keeps that structure.

**Checks** are protocol validations GrantCentral runs on every response, each
citing the spec section. Examples: `state` matches, `iss` matches (RFC 9207),
ID token signature, `nonce` and `at_hash`, `token_type` is `DPoP`,
`Cache-Control: no-store`, `cnf.jkt` matches the DPoP key. A failed
error-level check fails the step unless `expect = "error"`. Warnings and info
checks are reported without failing it.

## Logging in

| `login` | How the authorization response comes back |
|---|---|
| `system` (default) | Opens the system browser. A loopback listener catches the redirect, including `form_post` and fragment responses. |
| `chromium` | Headless Chromium runs `login_script` and intercepts the navigation to the redirect URI, so non-loopback redirect URIs work too. Failures save a screenshot to `.grantcentral/screenshots/`. |
| `http` | Follows redirects with a cookie jar; for test IdPs or SSO sessions that need no form. |
| `manual` | Prints the URL and waits for you to paste the redirected URL. |

`grantcentral run --login chromium` overrides every step, which is the usual
setting for CI. Point `--chrome` or `CHROME` at the browser, and add
`--no-sandbox` inside containers.

## CI

```yaml
- run: grantcentral -C idp-tests run --env staging --login chromium --no-sandbox --junit report.xml --json report.json
  env:
    GC_STAGING_CLIENT_SECRET: ${{ secrets.GC_STAGING_CLIENT_SECRET }}
    CHROME: /usr/bin/chromium
```

Exit codes: `0` all flows passed, `1` a flow failed, `2` usage or
configuration error. Reports and logs mask secret values, including their
URL-encoded and JSON-escaped forms, and `Authorization: Basic` headers.

### Container image

Each release publishes `ghcr.io/grantcentral/grantcentral` for `linux/amd64`
and `linux/arm64`, in two variants:

| Tag | Contents | Pick it for |
|---|---|---|
| `X.Y.Z`, `latest` | `grantcentral`, git, CA certificates and Chromium, with `CHROME` and `GRANTCENTRAL_NO_SANDBOX=true` set | `--login chromium` |
| `X.Y.Z-slim`, `slim` | the same without Chromium, tens of MB | `http` logins and token-only flows |

Pin a version in pipelines. Pre-releases get only their version tag and never
move `latest` or `slim`.

```sh
docker run --rm -v "$PWD:/work" --user "$(id -u):$(id -g)" -e GC_STAGING_CLIENT_SECRET \
  ghcr.io/grantcentral/grantcentral:X.Y.Z run --env staging --login chromium --junit report.xml
```

The entrypoint is `grantcentral` and the working directory is `/work`. The
image runs as a non-root user (UID 10001); `--user` runs it as you instead, so
the reports and screenshots it writes to `/work` belong to you. Pass `env`
secrets with `-e` (`-e NAME` copies the value from your shell). Some things
don't work in a container:

- `login = "system"` has no browser to open. Use `chromium` or `http`.
- `keyring` secrets have no Secret Service. Use `env`, or `file` with a mounted file.
- `login = "manual"` reads the pasted URL from stdin, so add `-it`.

The web UI needs a non-loopback bind and a fixed port to publish:

```sh
docker run --rm -v "$PWD:/work" -p 8080:8080 -e GRANTCENTRAL_BIND=0.0.0.0 -e GRANTCENTRAL_PORT=8080 \
  ghcr.io/grantcentral/grantcentral serve --no-open
```

Open the URL it prints. Its token travels over plain HTTP, so anyone who can
see the traffic can use the UI.

## The web UI

`grantcentral serve` binds to `127.0.0.1` and prints a URL carrying a random
token. Every API call must present that token. Requests whose `Host` header is
not `localhost` or an IP literal (any port) are refused, which blocks DNS
rebinding. The local process owns the filesystem, git, the loopback redirect
listener and the keychain.

`--bind` (or `GRANTCENTRAL_BIND`) takes another IP address to listen on, such
as `0.0.0.0` in a container, and `--port` (or `GRANTCENTRAL_PORT`) fixes the
port, which is otherwise a free one. Off loopback the UI is reachable from the
network and the token travels over plain HTTP, so `serve` warns about it.

The server checks the project files once a second, so files you add, remove or
edit in another editor show up in the UI right away. An open file reloads only
if it has no unsaved changes.

## Git

The web UI shows status and diffs, commit, pull
(fast-forward only) and push. It does this by running your installed `git`, so
SSH keys and credential helpers work as they do in your terminal. Branching
and conflict resolution are left to your usual git tools.

## Specification coverage

"e2e NN" refers to `e2e/project/flows/NN-*.toml`, which runs against a real
OpenID provider. "it" refers to `crates/core/tests/grants.rs`.

| Spec | Support | Tested by |
|---|---|---|
| RFC 6749 OAuth 2.0 | Authorization code, implicit/hybrid response types, password, client credentials and refresh grants; `client_secret_basic` (form-encoded before base64, per §2.3.1) and `_post`; error responses | e2e 02, 03, 09, 10, 12 |
| RFC 6750 Bearer tokens | header, form body and query; `WWW-Authenticate` parsing | e2e 02, it |
| RFC 6755 URN namespace | grant, token and assertion type URNs | n/a |
| RFC 6819 Threat model | basis for the audit and the negative-test flows | e2e 09 |
| RFC 7009 Revocation | `revoke` | e2e 02 |
| RFC 7521 / 7522 / 7523 Assertions | JWT bearer grant (generated or supplied), SAML 2.0 bearer grant (supplied assertion, base64url-encoded), `client_secret_jwt`, `private_key_jwt` | e2e 04, it |
| RFC 7591 / 7592 Dynamic registration | register, read, update, delete; the registered client is used for the rest of the flow | e2e 07 |
| RFC 7636 PKCE | S256, plain, none (negative tests) | e2e 03, 09, unit (RFC vector) |
| RFC 7638 JWK thumbprint | DPoP `jkt`, key IDs | unit (RFC vector) |
| RFC 7662 Introspection | `active`, `cnf` binding checks | e2e 02, 14 |
| RFC 8252 Native apps | loopback redirect listener, ephemeral ports, IP-literal check, system browser | e2e 03 |
| RFC 8414 AS metadata | well-known path insertion, issuer equality, TLS checks, `signed_metadata` decoding | e2e 01 |
| RFC 8628 Device grant | polling with `authorization_pending` and `slow_down`, user code checks | e2e 06 |
| RFC 8693 Token exchange | subject and actor tokens, `audience`, `resource`, `issued_token_type` check | e2e 08 |
| RFC 8705 Mutual TLS | `tls_client_auth` and `self_signed_tls_client_auth`, `mtls_endpoint_aliases`, certificate-bound token checks | e2e 14 |
| RFC 8707 Resource indicators | `resource` on authorize, token and device requests | e2e 04, 13 |
| RFC 9068 JWT access tokens | `validate_access_token`, `validate_jwt` | e2e 04 |
| RFC 9101 JAR | signed and encrypted (nested) request objects, `alg: none` for negative tests, by reference | e2e 04, 11 |
| RFC 9126 PAR | pushed requests, automatic when the server requires them | e2e 04, 05 |
| RFC 9207 Issuer identification | `iss` checks, including the ID-token exemption | e2e 03, 12 |
| RFC 9278 JWK thumbprint URI | `grantcentral jwk generate` and `jwk inspect` | unit |
| RFC 9396 RAR | `authorization_details` on authorize, PAR, token and device requests | e2e 05 |
| RFC 9449 DPoP | proofs with `ath`; server nonces at the AS and RS (with a fresh client assertion on retry); `dpop_jkt`; `cnf.jkt` checks | e2e 04, it |
| RFC 9470 Step-up | `insufficient_user_authentication` exposed as `step_up.acr_values` and `step_up.max_age` | e2e 13 |
| RFC 9700 Security BCP | `audit` checks plus negative tests: PKCE enforcement, code reuse, refresh rotation, redirect URI matching | e2e 01, 03, 09 |
| RFC 9701 JWT introspection | signed responses with `typ`, `iss` and `aud` checks | e2e 02 |
| RFC 9728 Resource metadata | `discover_resource`, `resource_metadata` in challenges | e2e 01, 13 |
| RFC 10017 Browser-based apps BCP | `audit --profile browser` (PKCE required, sender-constrained tokens or rotation), refresh rotation checks | e2e 01, 03 |
| RFC 10027 Cross-device BCP | user code lifetime and entropy checks, device code reuse test | e2e 06 |
| OpenID Connect Core / Discovery | ID token validation (signature, `iss`, `aud`, `azp`, `exp`, `nonce`, `at_hash`, `c_hash`, `auth_time`), UserInfo (JSON or JWT), `claims`, hybrid flow, `form_post` | e2e 03, 12 |
| JOSE (RFC 7515–7519, RFC 8725) | JWS: RS, PS, ES (P-256/384/521), EdDSA (Ed25519), HS. JWE: RSA-OAEP(-256/384/512), ECDH-ES(+A128KW/+A256KW) on P-256/384/521 and X25519, A*GCM and A*CBC-HS*. `alg: none` is never accepted from servers | unit (RFC 7516 A.1, RFC 7518 B.1 and C vectors) |

Not supported yet: JARM, CIBA, FAPI 2.0 profile checks, hosting request
objects by reference, and generating signed SAML assertions (supply your own).

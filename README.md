# GrantCentral

Test your OAuth 2.0 and OpenID Connect server the way a real client uses it.

GrantCentral is a test client for authorization servers. You describe flows
(log in, swap the code for tokens, call UserInfo, refresh, revoke, ...) in
small TOML files, keep them in git next to your other tests, and run them from
a browser UI on your machine or headless in CI.

```toml
name = "Authorization code with PKCE"

[[steps]]
type = "discover"

[[steps]]
id = "login"
type = "authorize"            # opens your browser, PKCE S256 by default

[[steps]]
id = "tok"
type = "token"
assert = ["status == 200", "claims.id_token.sub"]

[[steps]]
name = "a reused code is rejected"
type = "token"
code = "{{ steps.login.callback.code }}"
expect = "error"
```

## Why GrantCentral

- **Checks the specs for you.** Every response is validated against the RFCs
  (state, `iss`, ID token signature, `nonce`, DPoP binding, `Cache-Control`, ...),
  and each check cites the section it comes from.
- **Negative tests are first-class.** Drop parameters, send unsigned request
  objects, reuse codes, skip PKCE. GrantCentral sends the wrong request on
  purpose and checks that the server refuses it.
- **Covers modern OAuth.** PAR, JAR, DPoP, mTLS, RAR, token exchange, device
  flow, dynamic registration and more. See the
  [specification coverage](docs/reference.md#specification-coverage).
- **Plain files, in git.** Flows and environments are TOML with JSON schemas
  for editor completion. Secrets come from env variables, the OS keychain or
  files, and are masked in every report.
- **Local UI and CI from one engine.** `grantcentral serve` opens an editor
  and runner in your browser, and `grantcentral run` writes JUnit and JSON
  reports for your pipeline.

## Try it

```sh
cargo install grantcentral                 # or download a binary from the GitHub releases
grantcentral init my-idp-tests && cd my-idp-tests
$EDITOR environments/dev.toml              # point it at your server
grantcentral run                           # run every flow
grantcentral serve                         # or open the browser UI
```

Want to audit a server's metadata without writing anything?

```sh
grantcentral discover https://idp.example.com
```

## Documentation

- [Getting started](docs/getting-started.md): from install to your first passing flow.
- [Reference](docs/reference.md): projects, environments, every step type,
  templates, logins, CI and spec coverage.
- [Contributing](CONTRIBUTING.md): building from source, tests and releases.

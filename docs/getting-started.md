# Getting started

This guide takes you from nothing to a passing flow against your own
authorization server in about ten minutes. You need a client registered at the
server, with `http://127.0.0.1/callback` allowed as a redirect URI (any port).

## 1. Install

Download the binary for your platform from the GitHub releases (the Linux
`musl` builds are static and run on any distribution, x86_64 or aarch64), use
the [container image](reference.md#container-image), or install it with Cargo:

```sh
cargo install grantcentral
```

On macOS the release binaries are unsigned. Clear the quarantine flag once with
`xattr -d com.apple.quarantine grantcentral`. To build from source instead, see
[Contributing](../CONTRIBUTING.md).

## 2. Create a project

```sh
grantcentral init my-idp-tests
cd my-idp-tests
git init
```

That gives you:

```
grantcentral.toml            project name and default environment
environments/dev.toml        where your server lives and which client to use
environments/dev.local.toml  overrides for this machine only (git-ignored)
flows/                       three example flows
```

Each file starts with a `#:schema` comment, so editors with a TOML language
server (such as Even Better TOML in VS Code) complete and validate it as you type.

## 3. Point it at your server

Open `environments/dev.toml` and fill in your issuer and client ID:

```toml
[vars]
issuer = "https://idp.example.com"
client_id = "grantcentral-dev"
```

The client secret never goes in this file, since it's committed. Pick one:

```sh
grantcentral secret set dev/client_secret   # store it in the OS keychain
```

and switch the `[secrets]` entry to `{ keyring = "dev/client_secret" }`. Or export
`GC_DEV_CLIENT_SECRET`, which the file already reads. Or put a literal
`client_secret = "..."` in `dev.local.toml`.

Public clients can drop `client_secret` from `[client]` altogether.

## 4. Run the flows

```sh
grantcentral run
```

This runs all three example flows:

- **Metadata audit** checks the discovery document against the security BCPs.
- **Client credentials** gets a token, introspects it and revokes it.
- **Authorization code with PKCE** opens your browser so you can log in, then
  redeems the code, calls UserInfo and refreshes.

Run a single flow with `grantcentral run flows/audit.toml`, and add `-v` to see
every HTTP exchange. Exit code `0` means every flow passed.

Prefer clicking? `grantcentral serve` opens the same project in a browser UI with
an editor, a run button and git commit/push.

## 5. Write your own flow

A flow is a list of steps. Each step makes a request, GrantCentral validates the
response against the specs, and your `assert` expressions add your own checks.
Save this as `flows/reuse.toml`:

```toml
name = "Authorization codes are single-use"

[[steps]]
type = "discover"

[[steps]]
id = "login"
type = "authorize"

[[steps]]
type = "token"
assert = ["status == 200"]

[[steps]]
name = "the same code again is rejected"
type = "token"
code = "{{ steps.login.callback.code }}"
expect = "error"
assert = ["body.error == 'invalid_grant'"]
```

The last step is a negative test: `expect = "error"` means the step passes only
if the server refuses the request.

## 6. Run it in CI

Logins in CI can't use your browser, so script them with headless Chromium. Add
a `login_script` to the `authorize` step (the example flow has one commented
out), then:

```sh
grantcentral run --env dev --login chromium --junit report.xml
```

## Next steps

The [reference](reference.md) covers everything else: all step types, client
authentication methods, DPoP and mTLS, templates and expressions, login drivers
and the full specification coverage.

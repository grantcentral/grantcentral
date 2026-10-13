# AGENT.md

Notes for coding agents working on GrantCentral. `README.md` is the user-facing
reference for flow syntax, step types, CLI usage and spec coverage. Read it before
changing behavior, and keep it in sync with your changes.

## What this is

GrantCentral is a Rust workspace that tests OAuth 2.0 / OpenID Connect servers.
Users write flows as TOML files and run them from a CLI or a local web UI
(`grantcentral serve`). Both share one engine.

```
crates/core   grantcentral-core: file model, flow engine, OAuth/OIDC client. No UI code.
crates/cli    grantcentral: headless runner, `serve` (axum + crates/cli/web/index.html), JOSE/secret utilities
e2e/          node-oidc-provider test server (server.mjs) + a 14-flow suite in e2e/project/
```

## Scope (don't change without asking)

- **Client only.** Don't add a mock authorization server or resource server to the
  product. `e2e/server.mjs` exists for tests only.
- Git support is limited to status, diff, commit, pull (fast-forward only) and push,
  all done by shelling out to the user's `git` (`core/src/git.rs`). No branching or
  conflict UI.
- The web UI is served by the local binary. There is no hosted or WASM build.

## Commands

```sh
cargo fmt --all --check                              # CI enforces this (rustfmt.toml: max_width 140)
cargo clippy --workspace --all-targets -- -D warnings # CI enforces this: no warnings allowed
cargo test --workspace                               # unit tests, wiremock integration tests (core/tests/grants.rs)
cargo build -p grantcentral && e2e/run.sh            # e2e against the local OP (needs Node 22+, openssl)
CHROME=/path/to/chrome e2e/run.sh                    # also runs the flows tagged `chromium`
```

`e2e/run.sh` uses `target/debug/grantcentral`, so build it first. Pass extra
arguments through to `grantcentral run`, e.g. `e2e/run.sh --tag smoke`.
Without Chrome, the script skips the `chromium`-tagged flows.

## Architecture

- `model.rs`: serde + schemars types for every file a user edits. `StepKind` is an
  internally tagged enum (`type = "..."`), and the variant doc comments become the
  JSON schema descriptions. `lib.rs::schemas()` exports those schemas.
- `engine.rs`: `run_flow` / `start_run`. For each step it evaluates `when`, renders
  the step through templates, dispatches it, then applies `expect`, `assert` and
  `capture`. Protocol helpers receive `Run`, which provides `check()`, `log()`,
  `endpoint()`, client settings and session state.
- `oauth/mod.rs::execute` maps each `StepKind` to its implementation in `discovery.rs`,
  `authorize.rs`, `token.rs`, `endpoints.rs` or `audit.rs`.
- `template.rs`: minijinja environment, including the custom filters and functions
  (`jwt`, `b64url`, `sha256`, `now()`, `random(n)`).
- `login.rs`: user-agent drivers (`system`, `chromium`, `http`, `manual`) and the
  loopback redirect listener. Chromium support sits behind the default `chromium` feature.
- `jose.rs`: built on josekit. Never accept `alg: none` from a server.
- `report.rs`: `RunReport`, checks with `Severity`, and `redacted()`.
- `project.rs`: project discovery and loading, `init` scaffolding (from
  `core/scaffold/`, embedded with `include_str!`), and environment layering.
- `secrets.rs`: resolves `env`, `keyring`, `file` and literal secrets.

### Adding a step type

1. Define a `FooStep` struct and add a `StepKind::Foo` variant with a doc comment
   in `model.rs`. Add the variant to `type_name()` too.
2. Implement it in the matching `oauth/*.rs` file and add an arm to `oauth/mod.rs::execute`.
3. Add a row to the step table in `README.md`, plus an e2e flow or a wiremock test.
4. Any new spec support also needs a row in README's "Specification coverage" table,
   naming the test that covers it.

## Conventions

- **Checks cite the spec.** Use `run.check(name, passed, Severity, detail, Some("RFC NNNN §x.y"))`.
  `Error` fails the step unless the step has `expect = "error"`. `Warning` and `Info`
  are reported without failing it.
- **Negative tests are a feature.** Don't add validation that stops users from
  sending malformed requests on purpose (`params`, `remove`, `pkce = "none"`,
  `request_object = "unsigned"`, `duplicate_params`, ...). Validate server
  *responses* strictly. Leave user *requests* alone.
- **Secrets must never leak.** Anything a report or log emits has to go through
  `RunReport::redacted()`, which also masks URL-encoded and JSON-escaped forms and
  `Authorization: Basic` headers. Register new secret-like values in `redactions`.
- **Web UI security.** `serve` binds to `127.0.0.1` only, requires the random token on
  every API call (compared in constant time) and rejects non-loopback `Host`
  headers. Keep all three when you add routes in `cli/src/web.rs`.
- The web UI is a single file, `crates/cli/web/index.html`, embedded with
  `include_str!`. It has no build step and no npm dependencies. The only exception
  is the editor: a pre-built CodeMirror 5 bundle in `crates/cli/web/vendor/` (the
  rebuild recipe is in its header comment). It is served from `/vendor/*` without
  the token, but the `Host` check still applies. Never load scripts from a CDN, because
  the page holds the API token.
- CLI exit codes: `0` all flows passed, `1` a flow failed, `2` usage or config error.
- Shared dependency versions belong in `[workspace.dependencies]` in the root
  `Cargo.toml`. Prefer existing dependencies over new ones.
- Rust edition 2024, MSRV 1.88. On Windows and macOS, OpenSSL is always vendored.
- Commits follow Conventional Commits (`feat:`, `fix:`, `perf:`, `docs:`, `refactor:`, `ci:`, `chore:`;
  `!` or `BREAKING CHANGE:` for breaking changes). release-plz derives the version bump and
  changelog from them. Don't bump versions or edit `CHANGELOG.md` by hand.
- Code comments explain *why*, briefly. Doc comments on model types are
  user-facing because they become schema descriptions.

## Gotchas

- `e2e/project/keys/` contains test-only keys and secrets for the local OP. They
  are committed on purpose. Generated mTLS certificates go in `keys/generated/`
  (git-ignored).
- On failure, Chromium logins save screenshots to `.grantcentral/screenshots/` in
  the project directory. CI uploads them as artifacts.
- In containers or CI, Chromium needs `--no-sandbox` or `GRANTCENTRAL_NO_SANDBOX=true`.
- GitHub is a push mirror of a Forgejo repository, and each sync deletes refs that
  only exist on GitHub. CI on GitHub must never push branches or tags. Releases start
  from a `v*` tag pushed to Forgejo (see "Releases" in `README.md`).
- `redirect_uri` without a port means "pick a free port per run" (RFC 8252 §7.3).
  Don't "fix" it by adding a default port.

## Agent skills

### Issue tracker

Issues and specs live as local markdown files under `.scratch/<feature>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`), recorded as a `Status:` line in each issue file. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root, created only when needed. See `docs/agents/domain.md`.

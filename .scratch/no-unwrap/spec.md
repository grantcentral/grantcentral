# No unwrap or expect: clippy restriction lints

Status: ready-for-agent

## Problem Statement

GrantCentral's CI already runs `cargo clippy --workspace --all-targets -- -D warnings`, but only with clippy's default lints. Those defaults don't flag `unwrap()`, `expect()` or `panic!`, so nothing stops non-test code from crashing the process. There are 40 such sites today: 26 `unwrap` calls and 14 `expect` calls.

For a CLI that runs in pipelines, a panic is the worst way to fail. It prints a Rust backtrace instead of a message that names the flow and step, and it exits with code 101 instead of the documented `1` (flow failed) or `2` (usage or config error), so CI can't tell what went wrong. In `serve`, a panic inside a handler drops the request, and a panic while a mutex is held poisons the run map. After that, every later `lock().unwrap()` panics too, and the web UI stops working until the process restarts.

The maintainer doesn't want `unwrap` or `expect` in the codebase. Right now that rule exists only in reviewers' heads, and reviews miss things.

## Solution

Turn on clippy's panic-related restriction lints for the whole workspace, and rewrite the 40 existing sites so the workspace passes them. Test code keeps `unwrap`, `expect` and `panic!`, because a panic is how a test fails.

After this change, an `unwrap()`, `expect()`, `panic!`, `todo!`, `unimplemented!`, `unreachable!` or `dbg!` in non-test code fails CI's existing clippy step. There is no exemption mechanism. A site that "can't fail" still returns or handles an error.

## User Stories

1. As the maintainer, I want CI to reject `unwrap()` in non-test code, so that I don't have to catch it in review.
2. As the maintainer, I want CI to reject `expect()` in non-test code, so that a message string can't be used to justify a panic.
3. As the maintainer, I want CI to reject `panic!`, so that the ban can't be dodged by matching and panicking by hand.
4. As the maintainer, I want CI to reject `todo!`, `unimplemented!` and `unreachable!`, so that placeholder panics never reach a release.
5. As the maintainer, I want CI to reject `dbg!`, so that debug output never reaches a release.
6. As the maintainer, I want the lints declared once at the workspace level, so that both crates (and any future crate) get the same rules.
7. As the maintainer, I want the lints set to `warn` and turned into errors by CI's `-D warnings`, so that a local `cargo build` or `cargo test` isn't blocked mid-edit while CI stays strict.
8. As a contributor, I want `unwrap`, `expect` and `panic!` allowed in `#[test]` functions, `#[cfg(test)]` modules and the integration tests, so that tests stay short.
9. As a contributor, I want AGENTS.md to state the rule and the preferred alternatives, so that I know what to write instead before CI tells me.
10. As a coding agent, I want the rule in AGENTS.md's Conventions, so that I don't generate `unwrap()` in the first place.
11. As a pipeline user, I want an internal failure to surface as an error naming the flow and step, so that the job log tells me what broke instead of showing a backtrace.
12. As a pipeline user, I want internal failures to exit through the documented exit codes, so that my pipeline can tell a failed flow from a configuration error.
13. As a `serve` user, I want a failure inside one run to leave the web UI working, so that I don't have to restart `grantcentral serve`.
14. As a `serve` user, I want a poisoned lock to be recovered from rather than cascade, so that one bad run doesn't break every later API call.
15. As a user of the `random(n)` template function, I want an RNG failure to fail the step with an error, so that a flow never runs with a missing or predictable value.
16. As a user relying on redaction, I want a report that fails to serialize to be an error, not an unredacted fallback, so that secrets still never leak.
17. As a user running the schema subcommand or `init`, I want a schema export failure reported as an error, so that I get a message and exit code `2` instead of a crash.
18. As a user writing DPoP flows, I want a missing DPoP key reported as a step error, so that a broken session state fails one step instead of the whole process.
19. As a user running discovery against a misbehaving server, I want a metadata body that isn't a JSON object reported as a failed check, so that GrantCentral judges the server instead of crashing on it.
20. As a user parsing `WWW-Authenticate` headers from odd servers, I want malformed headers turned into errors or skipped, so that a server's mistake doesn't crash the client.
21. As a user verifying JWTs, I want malformed input to give a JOSE error, so that a bad token from the server is reported as such.
22. As a user running `grantcentral init`, I want a scaffold path without a parent to give an error, so that `init` never panics on an odd target path.
23. As the maintainer, I want the rewrites to keep current behavior on the success path, so that the existing unit, wiremock and e2e tests keep passing unchanged.

## Implementation Decisions

**Lint configuration**

- A `[workspace.lints.clippy]` table in the root manifest sets `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `unreachable` and `dbg_macro` to `warn`. Both crate manifests opt in with `[lints] workspace = true`.
- `warn`, not `deny`: CI's existing `-D warnings` turns them into errors, and contributors aren't blocked while iterating locally.
- A root `clippy.toml` sets `allow-unwrap-in-tests`, `allow-expect-in-tests` and `allow-panic-in-tests` to `true`. This is needed because CI lints with `--all-targets`, and most of the codebase's 130 `unwrap` calls are in tests.
- **No local exemptions.** Non-test code gets no `#[allow]` or `#[expect]` for these lints. A site that can't fail in practice still handles the error.
- **No disguised panics.** A rewrite must not replace `unwrap` with another construct that panics but isn't linted (`copy_from_slice` on a length it assumes, indexing it assumes is in bounds, `unwrap_or_else(|_| panic!(..))`). Propagate or handle the error instead.
- Not enabled: `indexing_slicing` (151 hits, mostly JSON and string indexing, too noisy), `print_stdout` / `print_stderr` (a CLI is supposed to print), and the `pedantic` group (191 hits, unrelated style). Each can be considered separately.
- CI needs no change. The existing clippy step picks the lints up from the manifests.

**Rewriting the existing sites, by kind**

- **Mutex locks** (the HTTP exchange log in core, the run map in `serve`): recover from poisoning with `unwrap_or_else(PoisonError::into_inner)`. Both guarded values are append/pop logs or maps that stay consistent even if a holder panicked, so recovering is correct and matches what a non-poisoning mutex would do. Don't add `parking_lot` or any other dependency for this. A small shared helper per crate is fine if it reads better than repeating the call.
- **Serialization to `serde_json::Value`** (template context, step document, merged client config, report redaction, schema export): the functions that do this return `Result` and callers propagate with `?`. This affects a few signatures with few callers each:
  - `Run::ctx()` returns `Result<Value>`.
  - `ClientConfig::merged()` returns `Result<ClientConfig>`.
  - `RunReport::redacted()` returns `Result<RunReport>`. Its caller, the CLI's report writer, collects the results and fails before writing any file. It never falls back to the unredacted report.
  - `schemas()` returns `Result<Vec<..>>`. Its callers (the CLI subcommand that prints schemas, and the project helper that writes them to disk) already return `Result` and propagate it, so the CLI exits `2` on error.
- **JSON objects built with `json!` and then unwrapped with `as_object()`** (EC/OKP JWK export, client-assertion claims, client context assembly): build a `serde_json::Map` directly, or match on `Value::Object`, so that no unwrap is needed.
- **Values already validated earlier in the same function** (JWT segment split after the format check, the RSA member array conversion, a header tokenizer's `chars().next()`, `last_mut()` on a list just pushed to, discovery's `resp.json()` after a status check, `as_object()` on discovery metadata): use `let ... else` with a `bail!` or a failed check carrying the existing context, or restructure so that the type carries the invariant. Discovery metadata that isn't a JSON object is reported through the step's error, like other malformed metadata.
- **DPoP key access after `ensure_dpop_key`**: `ensure_dpop_key` returns the key (or a reference to it, and the thumbprint), so callers no longer reach back into `session` and unwrap. That removes the invariant instead of asserting it.
- **Crypto helpers in core's root module**:
  - `random_b64` returns `Result<String>`, since the OS RNG can fail. Its ~12 callers already mostly return `Result`. The `random(n)` template function maps the error to a minijinja error, so the step fails with a template error.
  - `sha256` returns its 32-byte array without `expect`. Either convert the digest with a fallible conversion and propagate it as `Result`, or keep the digest type and let callers use `as_ref()`. Pick whichever makes the call sites smaller, but don't use `copy_from_slice` (see "No disguised panics").
- **Scaffolding** (`init` creating parent directories): a path without a parent becomes an error naming the path.

**Documentation**

- AGENTS.md "Conventions" gets one bullet: no `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!` or `dbg!` outside tests, with no `#[allow]` / `#[expect]` exemptions; propagate with `?` and `anyhow::Context`, and recover from mutex poisoning with `PoisonError::into_inner`. The Commands block already shows the clippy command and doesn't change.
- README doesn't change. The rule is for contributors, not users.

## Testing Decisions

- A good check here asserts what users and CI see: clippy passes or fails, and flows give the same results. It doesn't assert how each rewritten site handles its new error branch. Most of those branches can't be triggered from outside without fault injection, and tests that reach inside to force them would test the implementation, not behavior.
- **Seams: existing checks only.** No new tests.
  - CI's clippy step (`cargo clippy --workspace --all-targets -- -D warnings`) enforces the lints. To show the lints are on, an `unwrap()` added temporarily to a non-test function must make that command fail. The PR records that this was tried, and the `unwrap()` is not committed.
  - `cargo test --workspace` (unit tests and the wiremock tests in core's integration tests) shows the success paths didn't change. Prior art: the redaction test in the report module and the discovery URL tests already exercise rewritten functions.
  - `cargo build -p grantcentral && e2e/run.sh` (and the `chromium`-tagged flows when Chrome is available) shows that real flows against the local OP still behave the same, including discovery, DPoP, client assertions and the template `random(n)` function.
  - `cargo fmt --all --check` keeps passing.

## Out of Scope

- `indexing_slicing`, `print_stdout`, `print_stderr`, `clippy::pedantic` and other restriction lints. These can be separate decisions later.
- Removing `unwrap`, `expect` or `panic!` from tests.
- Replacing `std::sync::Mutex` with a non-poisoning mutex or adding any other dependency.
- A panic hook, or `catch_unwind` around runs or `serve` handlers. Once the code doesn't panic, these aren't needed. Add them later only if a dependency is found to panic in practice.
- Mapping specific internal errors to new exit codes. Errors go through the existing `0` / `1` / `2` paths.
- Panics inside dependencies (reqwest, chromiumoxide, aws-lc-rs, minijinja). Only GrantCentral's own code is linted.

## Further Notes

- Counts at the time of writing (non-test code): 26 `unwrap`, 14 `expect`, 0 `panic!`, `todo!`, `unimplemented!`, `unreachable!` or `dbg!`. They're spread over core's engine, HTTP, JOSE, model, discovery, endpoints, token, DPoP, project and report modules, its root module, and the CLI's web server. Re-run `cargo clippy --workspace -- -W clippy::unwrap_used -W clippy::expect_used` for the current list before starting.
- Land the lint configuration and the rewrites in one commit (`refactor:` or `fix:`), so the build is never red in between.
- `clippy.toml`'s `allow-*-in-tests` options cover `#[test]` functions and `#[cfg(test)]` code. If a helper in the integration tests that isn't a `#[test]` function still gets flagged, give that test file a file-level `#![allow(clippy::unwrap_used, clippy::expect_used)]`. That's test code, so the no-exemptions rule doesn't apply to it.

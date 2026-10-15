# 03: Make RNG and hashing failures errors

**What to build:** If the OS random number generator fails, the step fails with an error, and a flow never runs with a missing or predictable value. This covers `state`, `nonce`, PKCE verifiers, `jti` values and the `random(n)` template function. SHA-256 hashing no longer uses `expect`. See the spec (`../spec.md`), "Rewriting the existing sites, by kind" → "Crypto helpers in core's root module".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `random_b64` returns `Result<String>`, and its ~12 callers propagate with `?`.
- [ ] The `random(n)` template function maps an RNG error to a minijinja error, so the step fails with a template error naming the cause.
- [ ] `sha256` has no `expect`. It either returns `Result` or exposes the digest so callers use `as_ref()`, whichever makes the call sites smaller. It doesn't use `copy_from_slice` or any other construct that panics silently.
- [ ] aws-lc-rs stays the only crypto stack.
- [ ] `cargo clippy --workspace -- -W clippy::unwrap_used -W clippy::expect_used` reports none of these sites.
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` and `e2e/run.sh` pass, including the flows that use PKCE, DPoP, client assertions and `random(n)`.
- [ ] Committed as `refactor:` (or `fix:`). No version bump and no `CHANGELOG.md` edit.

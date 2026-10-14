# 05: Turn on the lints

**What to build:** CI rejects `unwrap()`, `expect()`, `panic!`, `todo!`, `unimplemented!`, `unreachable!` and `dbg!` in non-test code, and tests keep using them freely. AGENTS.md states the rule, so contributors and agents know what to write instead. See the spec (`../spec.md`), "Lint configuration" and "Documentation".

**Blocked by:** 01, 02, 03, 04

**Status:** ready-for-agent

- [ ] The root manifest has a `[workspace.lints.clippy]` table setting `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `unreachable` and `dbg_macro` to `warn`. Both crates opt in with `[lints] workspace = true`.
- [ ] A root `clippy.toml` sets `allow-unwrap-in-tests`, `allow-expect-in-tests` and `allow-panic-in-tests` to `true`. If an integration-test helper outside a `#[test]` function is still flagged, that test file gets a file-level allow.
- [ ] Non-test code has no `#[allow]` or `#[expect]` for these lints. Any site that tickets 01–04 missed is rewritten here under the same rules.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes, and the CI workflow is unchanged.
- [ ] The PR records a trial run: an `unwrap()` added temporarily to a non-test function made that command fail. The `unwrap()` is not committed.
- [ ] AGENTS.md "Conventions" has one new bullet. It bans these constructs outside tests with no exemptions, and says to propagate with `?` and `anyhow::Context` and to recover from mutex poisoning with `PoisonError::into_inner`.
- [ ] `cargo fmt --all --check`, `cargo test --workspace` and `e2e/run.sh` pass.
- [ ] Committed as `ci:` (or `chore:`). No version bump and no `CHANGELOG.md` edit.

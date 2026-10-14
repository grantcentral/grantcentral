# 01: Recover from poisoned locks instead of panicking

**What to build:** A panic while a lock is held no longer turns into a panic on every later access. The HTTP exchange log in core and the run map in `serve` recover from a poisoned mutex and keep working, so one bad run doesn't break the web UI until `grantcentral serve` is restarted. See the spec (`../spec.md`), "Rewriting the existing sites, by kind" → "Mutex locks".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Every `lock().unwrap()` on the HTTP exchange log (record, forget-last, drain) and on the `serve` run map (start, event loop, poll, input, cancel) is replaced with poison recovery (`unwrap_or_else(PoisonError::into_inner)`). Repeating it inline or using a small helper per crate are both fine.
- [ ] No new dependency (no `parking_lot`), and `std::sync::Mutex` stays.
- [ ] The `serve` token and `Host` checks are unchanged.
- [ ] `cargo clippy --workspace -- -W clippy::unwrap_used -W clippy::expect_used` reports no lock-related sites.
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` and `e2e/run.sh` pass.
- [ ] Committed as `fix:`. No version bump and no `CHANGELOG.md` edit.

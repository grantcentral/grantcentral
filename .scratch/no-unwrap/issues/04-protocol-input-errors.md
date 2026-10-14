# 04: Turn bad server input into errors

**What to build:** Bad input from a server no longer crashes GrantCentral. A malformed JWT, discovery metadata that isn't a JSON object, or an odd `WWW-Authenticate` header produces a failed check or step error that names the problem, so GrantCentral judges the server instead of panicking. The DPoP and `init` code drop their unwraps the same way. See the spec (`../spec.md`), "Rewriting the existing sites, by kind" → "Values already validated earlier", "DPoP key access" and "Scaffolding".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] JOSE: the JWT signature split, the RSA member array conversion and the EC/OKP JWK export no longer unwrap. They use `let ... else` with `bail!`, or build a `serde_json::Map` directly.
- [ ] Discovery: a metadata body that isn't a JSON object, or a response that fails to parse after the status check, is reported through the step's error like other malformed metadata. The insecure-endpoint scan no longer unwraps.
- [ ] `WWW-Authenticate` parsing: the tokenizer and the parameter-assignment code no longer unwrap. A malformed header gives an error or skips the bad part, but never panics.
- [ ] Client assertions: extra `assertion_claims` are merged without `as_object_mut().unwrap()`.
- [ ] DPoP: `ensure_dpop_key` returns the key and thumbprint (or references to them), and the proof and `jkt` helpers use the returned values instead of unwrapping session state.
- [ ] `init`: a scaffold path with no parent directory gives an error naming the path.
- [ ] No rewrite uses another construct that panics silently, such as assumed-in-bounds indexing, `copy_from_slice`, or `unwrap_or_else(|_| panic!(..))`.
- [ ] Negative tests still work: user *requests* are not newly validated. Only handling of server *responses* changes.
- [ ] `cargo clippy --workspace -- -W clippy::unwrap_used -W clippy::expect_used` reports none of these sites.
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (including the discovery and wiremock tests) and `e2e/run.sh` pass.
- [ ] Committed as `fix:`. No version bump and no `CHANGELOG.md` edit.

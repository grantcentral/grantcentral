# 02: Return serialization failures as errors

**What to build:** Converting GrantCentral's own types to and from JSON no longer panics. The template context, the step document, merged client config, report redaction and schema export return errors that the run reports through its normal paths. Redaction never falls back to an unredacted report. See the spec (`../spec.md`), "Rewriting the existing sites, by kind" → "Serialization to `serde_json::Value`" and "JSON objects built with `json!`".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `Run::ctx()` returns `Result<Value>`, and its callers in the engine and login drivers propagate with `?`.
- [ ] `ClientConfig::merged()` returns `Result<ClientConfig>`, and its callers in the engine and environment layering propagate.
- [ ] `RunReport::redacted()` returns `Result<RunReport>`. The CLI's report writer collects the results and fails before writing any JUnit or JSON file. No code path writes the unredacted report instead.
- [ ] `schemas()` returns `Result`. The schema subcommand and the project helper that writes the schema files propagate it, so a failure exits with code `2`.
- [ ] The step document's `checks` serialization and the client-context assembly in the engine no longer unwrap: the first propagates its error, and the second builds a `Map` directly or matches on `Value::Object`.
- [ ] Existing tests that call these functions (in `#[cfg(test)]` code) are updated to unwrap the `Result`, which is allowed in tests.
- [ ] `cargo clippy --workspace -- -W clippy::unwrap_used -W clippy::expect_used` reports none of these sites.
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (including the redaction test) and `e2e/run.sh` pass.
- [ ] Committed as `refactor:` (or `fix:`). No version bump and no `CHANGELOG.md` edit.

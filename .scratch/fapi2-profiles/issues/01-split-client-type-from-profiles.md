# 01: Split client type from profiles

**What to build:** The audit's client-type setting gets its own name, and a new, separate `profiles` setting is introduced, with `fapi2` as its only value so far. Users write `client_type = "confidential" | "browser" | "native"` on the `audit` step and `--client-type` on `grantcentral discover`. They list profiles in `[client] profiles = [...]`, which merges like every other `[client]` field: a flow's list replaces the environment's, and `[]` means no profiles. They can also override profiles on the `audit` step with its own `profiles`, which falls back to the merged client's list when unset. `discover` takes a repeatable `--profile <name>`. No checks change under `fapi2` yet. This ticket lays the groundwork for the profile rules in 02 and 03. See the spec (`../spec.md`), `CONTEXT.md` and ADR 0001.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The `audit` step accepts `client_type`. The old `profile` field still works as an alias and logs a deprecation warning.
- [ ] `grantcentral discover` accepts `--client-type <confidential|browser|native>` (default confidential) and a repeatable `--profile <name>`. For one release, `--profile confidential|browser|native` maps to the client type and prints a deprecation warning.
- [ ] `ClientConfig` has `profiles`, an optional list of profile names. A flow's value replaces the environment's, and an empty list turns profiles off. The `audit` step has an optional `profiles` override.
- [ ] Profile names are a typed, closed enum (today only `fapi2`, meaning FAPI 2.0 Security Profile Final), so the JSON schema lists the values. An unknown name is a config error (exit 2) whose message lists the known names.
- [ ] A client type of `browser` or `native` combined with `fapi2` is a config error (exit 2), not a check.
- [ ] `profiles`, `client_type` and the deprecated alias have user-facing doc comments that show up in the exported schema.
- [ ] Tests cover the deprecated `profile = "browser"` alias on the audit step and the browser + `fapi2` config error.
- [ ] README documents `client_type`, `profiles` and the deprecations, using the words "profile checks", never "conformant", "certified" or "compliant".
- [ ] Committed as `feat!:`, because the rename is breaking. No version bump and no `CHANGELOG.md` edit.
- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` and `e2e/run.sh` pass.

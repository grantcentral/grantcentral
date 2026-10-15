# 04: e2e: FAPI client, happy-path flow and negative flow

**What to build:** The e2e suite proves the `fapi2` profile end to end against node-oidc-provider. One dedicated client gets the OP's FAPI 2.0 profile, so the existing flows are unaffected. A happy-path flow passes all FAPI 2.0 profile checks. A negative flow shows that the server enforces the profile rather than merely advertising it.

**Blocked by:** 02 (`fapi2` metadata audit), 03 (`fapi2` checks on live responses)

**Status:** ready-for-agent

- [ ] The e2e server turns on node-oidc-provider's FAPI 2.0 profile for one dedicated client only. The existing 14 flows still pass unchanged.
- [ ] A happy-path flow under `profiles = ["fapi2"]` uses PAR, PKCE S256, DPoP and `private_key_jwt`, includes an `audit` step, and reports "FAPI 2.0 profile checks passed".
- [ ] A negative flow covers no PAR, no PKCE, `client_secret_*` and bearer token use, each with `expect = "error"`. Requests are sent exactly as written.
- [ ] README "Specification coverage" rows point at these flows where they cover a rule.
- [ ] `e2e/run.sh` passes. `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test --workspace` also pass.

# 02: `fapi2` metadata audit

**What to build:** When `fapi2` is active for an `audit` step (through the merged client config or the step's own `profiles`), or when `grantcentral discover --profile fapi2` runs, the metadata audit holds the server to the FAPI 2.0 Security Profile (Final, Feb 2025). A server that advertises RS256, makes PAR optional or offers `client_secret_*` fails the audit with `Error`, not `Info`. A passing report says "FAPI 2.0 profile checks passed".

**Blocked by:** 01 (Split client type from profiles)

**Status:** ready-for-agent

- [ ] Existing checks that FAPI tightens keep one check name and get the raised severity, with the FAPI citation appended to the base citation. One fact produces exactly one check.
- [ ] `Error` checks under `fapi2`:
  - [ ] PAR required (`require_pushed_authorization_requests` true).
  - [ ] PKCE S256 advertised.
  - [ ] Only the `code` response type offered.
  - [ ] `authorization_response_iss_parameter_supported` true.
  - [ ] DPoP or mTLS-bound access tokens advertised.
  - [ ] Token endpoint auth limited to `private_key_jwt` and mTLS.
  - [ ] Signing algs limited to PS256, ES256 and EdDSA, with RS256 named explicitly when present.
- [ ] Severity mapping: a "shall" rule is `Error` and a "should" rule is `Warning`. A rule that metadata can't confirm is a `Warning` whose detail names the flow or live check that settles it.
- [ ] Combining profiles is an order-independent fold: the maximum severity, the intersection of allowed sets, the union of profile-only checks and the concatenation of citations.
- [ ] Every FAPI citation names the exact section of the published Final text. Section numbers were checked against that text, not against the backlog or the spec.
- [ ] Profiles never add steps. The audit only runs where a flow has an `audit` step.
- [ ] A passing report under a profile says "FAPI 2.0 profile checks passed". No report, README or UI text says "conformant", "certified" or "compliant".
- [ ] `audit_metadata` unit tests cover:
  - [ ] each `fapi2` rule with its severity;
  - [ ] tightened checks keeping one name with both citations;
  - [ ] strictest-wins when tightenings overlap;
  - [ ] the deprecated `--profile browser` mapping.
- [ ] A wiremock test runs an `audit` step under `fapi2` against weak metadata and inspects the report. The test also covers the audit step's own `profiles` override.
- [ ] README: the audit step row and "Specification coverage" rows for the FAPI 2.0 metadata rules, each naming its test.
- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` and `e2e/run.sh` pass.

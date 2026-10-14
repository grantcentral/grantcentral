# 03: `fapi2` checks on live responses

**What to build:** When `fapi2` is in a flow's merged client config, GrantCentral applies the profile's rules to what the server actually returns during a run, not only to what it advertises. A server that signs with RS256, issues an unbound bearer token or hands out a long-lived PAR request URI fails the step. Requests are never validated against the profile: FAPI negative tests (`client_secret_basic`, RS256, no PAR, `pkce = "none"`) go out exactly as written.

**Blocked by:** 01 (Split client type from profiles)

**Status:** ready-for-agent

- [ ] Server-signed JWTs that already go through validation are checked against the FAPI JWS alg allow-list (PS256, ES256, EdDSA): ID tokens, JWT access tokens, signed introspection responses and signed userinfo responses. An alg outside the list is an `Error`.
- [ ] A token response carrying an unbound access token (bearer `token_type`, no DPoP and no `cnf` binding) is an `Error`.
- [ ] A PAR response with `expires_in` over 600 s is an `Error`.
- [ ] Each check follows the existing convention: name, pass/fail, severity, detail, and a FAPI 2.0 Final section citation (checked against the published text). Where a base check already covers the same fact, it is tightened in place rather than duplicated.
- [ ] Before adding any refresh-token rule, check what the FAPI 2.0 Final text says about rotation. The existing "refresh token rotated" check already passes for confidential, sender-constrained clients.
- [ ] Profile checks show up in the web UI run view like any other check, with their citations.
- [ ] Wiremock tests (temp project with an environment file):
  - [ ] Each live check fails the step: an alg outside the allow-list, an unbound bearer token, and PAR `expires_in` > 600.
  - [ ] A flow's `profiles` replaces the environment's list, and `profiles = []` turns them all off.
  - [ ] `client_secret_basic`, RS256 and no-PAR requests reach the mock unchanged under `fapi2`.
  - [ ] A profile `Error` fails the flow with exit code 1.
- [ ] README: "Specification coverage" rows for the live FAPI 2.0 checks, each naming its test.
- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` and `e2e/run.sh` pass.

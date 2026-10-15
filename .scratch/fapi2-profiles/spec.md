# Profiles: FAPI 2.0 Security Profile checks

Status: ready-for-agent

## Problem Statement

People testing authorization servers that target FAPI 2.0 (open banking, open finance, high-assurance APIs) can already drive every protocol feature the FAPI 2.0 Security Profile needs with GrantCentral (PAR, PKCE, DPoP, mTLS, `private_key_jwt`, RFC 9207). They cannot ask GrantCentral to hold the server to that profile's rules. A server that offers RS256, makes PAR optional, issues bearer tokens or hands out long-lived PAR request URIs passes today with at most `Info` findings. The user has to know every FAPI rule and hand-write `assert` expressions for each.

The audit setting that exists today is also called `profile`, but it means something else: the client type (confidential, browser, native). That leaves no clean word for a set of spec rules, and it can't express two independent things at once, such as "audit for a browser client under OAuth 2.1" later on.

## Solution

Introduce **profiles**: named, versioned sets of spec rules that tighten checks. The first profile is `fapi2` (FAPI 2.0 Security Profile, Final). Users list the profiles that apply in `[client] profiles = [...]`. An environment sets the default and a flow can override it. GrantCentral then:

- Audits metadata against the profile when a flow has an `audit` step (or with `grantcentral discover --profile fapi2`).
- Applies the profile's rules to live server responses during a run.
- Never changes what the client sends, so FAPI negative tests keep working.

The old client-type setting is renamed to **client type** (`client_type = "confidential" | "browser" | "native"`). The old `profile = "browser"` spelling keeps working for one release with a deprecation warning. Reports say "FAPI 2.0 profile checks passed", never "conformant" or "certified".

## User Stories

1. As a FAPI implementer, I want to set `profiles = ["fapi2"]` in my environment's `[client]`, so that every flow in that environment holds the server to FAPI 2.0 rules.
2. As a FAPI implementer, I want an `audit` step to report FAPI 2.0 metadata violations, so that I can see from discovery alone where my server falls short.
3. As a FAPI implementer, I want the audit to fail with `Error` when PAR isn't required (`require_pushed_authorization_requests` not true), so that a server that allows front-channel requests can't pass.
4. As a FAPI implementer, I want the audit to fail when PKCE S256 isn't advertised, so that missing PKCE support is caught.
5. As a FAPI implementer, I want the audit to fail when response types other than `code` are offered, so that hybrid and implicit flows are flagged.
6. As a FAPI implementer, I want the audit to fail when `authorization_response_iss_parameter_supported` isn't true, so that missing mix-up protection is caught.
7. As a FAPI implementer, I want the audit to fail when neither DPoP nor mTLS-bound access tokens are advertised, so that a server that can only issue bearer tokens is flagged.
8. As a FAPI implementer, I want the audit to fail when token endpoint auth methods other than `private_key_jwt` and mTLS are offered, so that `client_secret_*` support is flagged.
9. As a FAPI implementer, I want the audit to fail when signing algs outside PS256, ES256 and EdDSA are advertised (with RS256 named explicitly), so that weak or non-FAPI algorithms are caught.
10. As a FAPI implementer, I want a rule that metadata can't confirm to show up as a `Warning` naming the flow or live check that settles it, so that I know what to run next instead of getting a false failure.
11. As a FAPI implementer, I want a check that a profile tightens to appear once, with its raised severity and both the base and FAPI citations, so that the report doesn't show two verdicts for one fact.
12. As a FAPI implementer, I want an ID token signed with an alg outside the FAPI allow-list to fail the step during a run, so that what the server actually does is checked, not just what it advertises.
13. As a FAPI implementer, I want other JWTs the server signs (JWT access tokens, signed introspection and userinfo responses) checked against the same allow-list, so that no signed response slips through.
14. As a FAPI implementer, I want a bearer (unbound) access token in a token response to fail the step, so that a server that ignores DPoP or mTLS binding is caught.
15. As a FAPI implementer, I want a PAR response with `expires_in` over 600 seconds to fail the step, so that long-lived request URIs are caught.
16. As a FAPI implementer, I want to deliberately send `client_secret_basic`, `RS256`, no PAR or `pkce = "none"` under `fapi2`, with the request sent exactly as written, so that I can test that my server rejects them.
17. As a FAPI implementer, I want a negative-test flow pattern (`expect = "error"`) for no PAR, no PKCE, `client_secret_*` and bearer token use, so that I can prove my server enforces the profile and doesn't merely advertise it.
18. As a FAPI implementer, I want to test the 60-second authorization code lifetime with a flow that waits and then redeems, so that a rule the client can't observe directly can still be verified.
19. As a FAPI implementer, I want a passing report to say "FAPI 2.0 profile checks passed", so that I don't mistake GrantCentral for the OpenID Foundation conformance suite.
20. As a flow author, I want a flow's `profiles` to replace the environment's list, so that I can write a plain RFC 6749 smoke flow in a FAPI environment.
21. As a flow author, I want `profiles = []` in a flow to turn off every profile for that flow, so that opting out is explicit and easy.
22. As a flow author, I want setting `profiles` never to add steps to my flow, so that a flow does exactly what its file says.
23. As a flow author, I want the `audit` step to accept its own `profiles` override, so that one flow can audit against a different profile than the rest of the environment.
24. As a flow author, I want to write `client_type = "browser"` on the `audit` step, so that the setting's name says what it is.
25. As an existing user, I want `profile = "browser"` on the `audit` step to keep working for one release with a deprecation warning, so that upgrading doesn't break my flows.
26. As an existing user, I want `grantcentral discover --profile browser` to keep working for one release with a deprecation warning, so that my scripts don't break.
27. As a CLI user, I want `grantcentral discover <issuer> --client-type confidential --profile fapi2`, so that I can audit a server against FAPI 2.0 without a project.
28. As a CLI user, I want to be able to repeat `--profile`, so that I can audit against several profiles once more exist.
29. As a user, I want `client_type = "browser"` (or `"native"`) combined with `fapi2` to be a config error (exit 2), so that a combination that can't be answered fails loudly instead of producing a meaningless report.
30. As a user, I want an unknown profile name to be a config error (exit 2) that lists the known profiles, so that typos are caught.
31. As a user of several profiles, I want a check that more than one profile tightens to take the strictest severity and cite every source, so that adding a profile can only make results stricter and the order I list them in doesn't matter.
32. As a CI user, I want profile violations at `Error` severity to fail the flow (exit 1), so that FAPI regressions break the build.
33. As a web UI user, I want profile checks to appear in the run view like any other check, with their citations, so that the UI and CLI agree.
34. As a schema-aware editor user, I want `profiles` and `client_type` in the JSON schema with descriptions, so that my editor completes them and explains them.
35. As a reader of the README, I want the step table, the client settings and the specification coverage table to document `fapi2`, so that I can tell what's covered and which test covers it.
36. As a maintainer, I want the e2e suite to skip the slow code-lifetime flow by default, so that ordinary e2e runs don't take an extra minute.

## Implementation Decisions

- **Glossary and ADR.** Use the terms in `CONTEXT.md`: Check, Audit, Client type, Profile, Profile checks, Conformance. ADR 0001 records the split between client type and profiles.
- **Model.**
  - `ClientConfig` gains `profiles`: an optional list of profile names. It merges like every other `[client]` field, so a flow's value replaces the environment's entirely, and an empty list means no profiles.
  - The `audit` step gains `client_type` and an optional `profiles` override. When unset, the step's `profiles` falls back to the merged client's.
  - The audit step's old `profile` field stays as a deprecated alias of `client_type` for one release and logs a deprecation warning when used. Doc comments on all of these are user-facing schema descriptions.
- **Profile names.** Profile names are a closed set. Today that set is `fapi2`, meaning FAPI 2.0 Security Profile Final. Unknown names are a config error (exit 2) that lists the known names. A typed enum is preferred over free strings so the schema enumerates the values.
- **Audit.** The metadata audit takes the client type plus the list of active profiles.
  - Client type and `fapi2` conflict when the client type isn't confidential. That's a config error, not a check.
  - Under `fapi2`, existing checks are tightened in place: same check name, higher severity, and the FAPI citation appended to the base citation.
  - Profile-only checks (PAR required, response types limited to `code`, client auth limited to `private_key_jwt`/mTLS, signing algs limited to PS256/ES256/EdDSA) run only when the profile is active.
  - Severity mapping: a "shall" rule is `Error`, a "should" rule is `Warning`, and a rule metadata can't confirm is `Warning` with a detail naming what settles it.
- **Live checks.** When `fapi2` is active in the merged client config, response handling adds:
  - The JWS alg allow-list on ID tokens and on other server-signed JWTs that already go through validation (JWT access tokens, signed introspection and userinfo).
  - A failure when the token response carries an unbound access token: bearer `token_type` with no DPoP and no `cnf` binding.
  - PAR `expires_in` ≤ 600 s.

  These follow the existing check convention: name, pass/fail, severity, detail, spec citation.
- **Combining profiles.** Each profile only tightens: a higher severity, a smaller allowed set, or extra checks. Combining is therefore a fold that is independent of order: maximum severity, intersection of allowed sets, union of extra checks, concatenation of citations. One fact always produces one check.
- **Requests are never validated against a profile.** No profile changes, blocks or warns about what the client sends. This follows the AGENTS.md "negative tests are a feature" rule.
- **No implicit steps.** Profiles never add steps. An audit only runs where a flow has an `audit` step.
- **CLI.** `discover` gains `--client-type <confidential|browser|native>` (default confidential) and a repeatable `--profile <name>`. For one release, `--profile` also accepts `confidential|browser|native`, maps the value to client type and prints a deprecation warning. Client type and profile values never overlap, so the mapping is unambiguous.
- **Wording.** Reports, README and UI say "profile checks", never "conformant", "certified" or "compliant".
- **Release.** The rename breaks existing settings, so the change ships as a `feat!:` commit. Don't bump versions or edit `CHANGELOG.md` by hand.
- **Citations.** Cite the exact section of the FAPI 2.0 Security Profile (Final, Feb 2025) for every FAPI rule. Check section numbers against the published Final text rather than the backlog or this spec.

## Testing Decisions

- Good tests here assert on what users see: the `RunReport` (which checks exist, pass/fail, severity, citation), what was sent over the wire, and exit codes. Don't assert on internal helper structure.
- **Running a flow against a mock server** (prior art: the wiremock grant tests in the core crate's integration tests, which write a temp project, call `start_run` and inspect the report) is the main seam. Cover:
  - The live `fapi2` checks: an alg outside the allow-list, an unbound bearer token, and PAR `expires_in` > 600, each failing the step.
  - An `audit` step under `fapi2` with weak metadata.
  - The config error for a browser client with `fapi2`.
  - A flow's `profiles` replacing the environment's, and `[]` turning profiles off (via an environment file in the temp project).
  - Requests reaching the mock unchanged under `fapi2`: `client_secret_basic`, `RS256` and no PAR.
  - The deprecated `profile = "browser"` alias on the audit step.
- **`audit_metadata` unit tests** (prior art: the existing weak-metadata test in the audit module) hold the full metadata-rule matrix: each `fapi2` rule flagged with the right severity, tightened checks keeping one name with combined citations, and strictest-wins when tightenings overlap. The CLI `discover` command calls this function directly, so the deprecated `--profile browser` mapping is covered here rather than by a separate CLI test.
- **e2e** (prior art: the 14 flows in the e2e project, run by `e2e/run.sh` against node-oidc-provider):
  - Turn on node-oidc-provider's FAPI 2.0 profile for one dedicated client only, so the existing flows are unaffected.
  - Add a `fapi2` happy-path flow (PAR + PKCE S256 + DPoP + `private_key_jwt`, audit included).
  - Add a negative-test flow: no PAR, no PKCE, `client_secret_*` and bearer token use, all `expect = "error"`.
  - Add a code-lifetime flow (authorize, wait just over 60 s, redeem, `expect = "error"`) tagged `slow`. `e2e/run.sh` skips `slow` by default, the same way it skips `chromium` when no browser is available.
- `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test --workspace` must pass, as must `e2e/run.sh`.

## Out of Scope

- **The `oauth21` profile.** It waits until OAuth 2.1 is published as an RFC; it is still `draft-ietf-oauth-v2-1`. The list-valued `profiles` setting exists so it can be added without another breaking change.
- **FAPI 2.0 Message Signing.** It needs JARM first. It will become `fapi2_message_signing`, a profile that extends `fapi2`. Don't add "extends" until then.
- HTTP Message Signatures (RFC 9421).
- FAPI 1.0 Advanced.
- Conformance or certification claims, and anything that duplicates the OpenID Foundation conformance suite.
- Moving `client_type` into `[client]`. Live checks keep inferring public vs confidential from `auth_method`.
- Validating, blocking or warning about client requests under a profile.
- Scaffolding profile flows with `grantcentral init`.

## Further Notes

- The FAPI 2.0 and OAuth 2.1 entries in `BACKLOG.md` came before these decisions. Their main stale claim is that the authorization code lifetime is a live check. The client can't observe it, so it's tested by the slow e2e flow instead. Update the backlog when this lands.
- The existing "refresh token rotated" check already passes for confidential, sender-constrained clients whether or not tokens rotate. Before adding a profile-specific rule on refresh tokens, check what the FAPI 2.0 Security Profile Final text says about rotation.
- Profile names should stay stable once released. A future FAPI revision gets a new name rather than redefining `fapi2`.

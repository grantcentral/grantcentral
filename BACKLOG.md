# Backlog

## Smaller release binary

The release profile (`lto`, `codegen-units = 1`, `opt-level = "z"`, `strip`) plus a single
crypto stack (aws-lc-rs for TLS and JOSE; OpenSSL and josekit are gone) takes the Linux x86_64
binary to 11.1 MiB (v0.0.2, with vendored OpenSSL, was 16.8 MiB). What remains is mostly
dependencies (`cargo bloat --release --crates` on the old profile, so sizes are relative):

- **chromiumoxide (~3.7 MiB with `chromiumoxide_cdp`).** Already behind the `chromium`
  feature. Could ship a slim build without it, at the cost of a second artifact per target.
- **keyring (~1.6 MiB via zbus + secret-service on Linux).** That is the Secret Service
  backend itself; the only lighter Linux store is kernel keyutils, which doesn't persist
  across reboots. Probably keep.

Rejected from [min-sized-rust](https://github.com/johnthagen/min-sized-rust):

- `panic = "abort"` (would save ~2.8 MiB): `serve` relies on unwinding to contain a panicking flow or handler
  to its task (`engine.rs::start_run`, `web.rs` `spawn_blocking`); abort kills the server.
- Nightly-only flags (`build-std`, `-Zlocation-detail=none`, `-Zfmt-debug=none`,
  `immediate-abort`): CI and MSRV are stable.
- UPX: antivirus false positives, slower startup.

## JARM

[JARM](https://openid.net/specs/oauth-v2-jarm-final.html) (OpenID Final) signs the authorization
response, and can optionally encrypt it. Most of the pieces already exist: `authorize` takes
`response_mode`, the loopback listener catches query, fragment and `form_post` responses, and
`jose.rs` verifies JWS and decrypts JWE with `decryption_key`.

- Accept `response_mode = jwt | query.jwt | fragment.jwt | form_post.jwt`, and unwrap the `response`
  parameter into `callback` so that existing `state`/`iss`/`code` checks keep working.
- Checks: signature against the JWKS, `iss`, `aud` = client_id, `exp`, never `alg: none`. Cite
  JARM §2.4 / §4.
- `audit`: `authorization_signing_alg_values_supported` and `authorization_encryption_*`.
- e2e: node-oidc-provider `features.jwtResponseModes`.

## CIBA

[OpenID Connect CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
(Final). The user approves on another device, so the `login` drivers don't apply.

- **Poll mode first.** A new `backchannel_authorize` step (`login_hint` / `id_token_hint` /
  `login_hint_token`, `binding_message`, `user_code`, `requested_expiry`, a signed `request`), then
  the `token` step with `grant_type = urn:openid:params:grant-type:ciba` and `auth_req_id`. This can
  reuse the device grant's polling, which already handles `authorization_pending` and `slow_down`.
- **Ping and push** need a client notification endpoint that the AS can reach. The loopback
  listener only works when the AS runs locally, so add them later and only if someone needs them.
- e2e: node-oidc-provider `features.ciba`. Its `triggerAuthenticationDevice` hook can
  approve automatically.

## FAPI 2.0 profile checks

The [Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html) has been
Final since Feb 2025, and [Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html)
since Sep 2025. Every protocol feature the Security Profile needs already exists (PAR, PKCE, DPoP,
mTLS, `private_key_jwt`, RFC 9207). What's missing are the profile rules:

- `audit --profile fapi2`: PAR required (`require_pushed_authorization_requests`), PKCE S256,
  `response_type = code` only, `iss` parameter, DPoP or mTLS-bound tokens, client auth limited to
  `private_key_jwt`/mTLS, and signing algs limited to PS256/ES256/EdDSA (flag RS256).
- Response checks behind a client/flow `profile = "fapi2"` switch: ID token and JWT algs from the
  same allow-list, and the authorization code lifetime is at most 60 s (`expires_in` on the PAR
  response is at most 600 s).
- Negative-test flow: no PAR, no PKCE, `client_secret_*` auth and a bearer (unbound) token use
  must all be rejected.
- Message Signing composes JAR (exists), JARM (above) and RFC 9701 introspection (exists). Leave
  HTTP Message Signatures (RFC 9421) out until someone asks for them.
- e2e: node-oidc-provider `features.fapi` with `profile: '2.0'`.

## FAPI 1.0 Advanced (maybe)

Final since 2021 and superseded by 2.0, but still deployed in UK Open Banking, Brazil Open
Finance and Australia CDR. Beyond FAPI 2.0 plus JARM it adds little:

- `s_hash` validation in the ID token, plus the hybrid `code id_token` detached signature.
- Request object `exp - nbf` of at most 60 min, and the `x-fapi-interaction-id` echo on resource calls.
- `audit --profile fapi1`.

Do it after FAPI 2.0, and only if a user targets one of those ecosystems.

## OAuth 2.1 profile

No `oauth21` profile exists today. The current `audit` profiles already check most of its MUSTs
(PKCE, no implicit grant, no password grant, and refresh rotation for public clients), but they
cite RFC 9700 and RFC 10017, not 2.1. OAuth 2.1 is still an Internet-Draft
([draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)). Once it
becomes an RFC, add 2.1 section citations to the existing checks, plus the few 2.1-only
rules: PKCE required for every client, no bearer tokens in the query string (flag
`auth = "bearer_query"` in reports, but keep sending it, since negative tests need it), and exact
redirect URI matching (already covered by e2e 09).

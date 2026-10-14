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
mTLS, `private_key_jwt`, RFC 9207). What's missing are the profile rules.

Specified in `.scratch/fapi2-profiles/spec.md` (terms in `CONTEXT.md`, ADR 0001). In short:

- `[client] profiles = ["fapi2"]`, plus `client_type` replacing today's audit `profile`.
- `audit` checks: PAR required (`require_pushed_authorization_requests`), PKCE S256,
  `response_type = code` only, `iss` parameter, DPoP or mTLS-bound tokens, client auth limited to
  `private_key_jwt`/mTLS, and signing algs limited to PS256/ES256/EdDSA (flag RS256).
- Live response checks: ID token and JWT algs from the same allow-list, no unbound bearer tokens,
  and `expires_in` on the PAR response at most 600 s.
- The authorization code lifetime (at most 60 s) can't be seen by the client. A `slow`-tagged e2e
  flow tests it by waiting and then redeeming.
- Negative-test flow: no PAR, no PKCE, `client_secret_*` auth and a bearer (unbound) token use
  must all be rejected.
- Message Signing composes JAR (exists), JARM (above) and RFC 9701 introspection (exists). Once JARM
  lands it becomes a `fapi2_message_signing` profile that extends `fapi2`. Leave HTTP Message
  Signatures (RFC 9421) out until someone asks for them.
- e2e: node-oidc-provider `features.fapi` with `profile: '2.0'`, for one dedicated client only.

## FAPI 1.0 Advanced (maybe)

Final since 2021 and superseded by 2.0, but still deployed in UK Open Banking, Brazil Open
Finance and Australia CDR. Beyond FAPI 2.0 plus JARM it adds little:

- `s_hash` validation in the ID token, plus the hybrid `code id_token` detached signature.
- Request object `exp - nbf` of at most 60 min, and the `x-fapi-interaction-id` echo on resource calls.
- A `fapi1` profile.

Do it after FAPI 2.0, and only if a user targets one of those ecosystems.

## OAuth 2.1 profile

No `oauth21` profile exists today. The current client-type audit already checks most of its MUSTs
(PKCE, no implicit grant, no password grant, and refresh rotation for public clients), but it
cites RFC 9700 and RFC 10017, not 2.1. OAuth 2.1 is still an Internet-Draft
([draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)). Once it
becomes an RFC, add an `oauth21` profile (the `profiles` list from the FAPI 2.0 spec already
allows it): 2.1 section citations on the existing checks, plus the few 2.1-only rules: PKCE
required for every client, no bearer tokens in the query string (flag `auth = "bearer_query"` in
reports, but keep sending it, since negative tests need it), and exact redirect URI matching
(already covered by e2e 09).

## Multi-arch Alpine image on GHCR

Publish `ghcr.io/<owner>/grantcentral` for `linux/amd64` and `linux/arm64`. Docker on Apple
Silicon runs `linux/arm64`, so those two platforms cover Linux and macOS hosts. The current
`Dockerfile` is Debian-based and still installs `libssl3`, which nothing has needed since
OpenSSL was dropped.

- **Build static musl binaries, not in the Dockerfile.** Add `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-musl` to the release matrix, using the native `ubuntu-24.04-arm` runner
  for aarch64 rather than QEMU, which is very slow for a release build with LTO. aws-lc-sys,
  zbus and chromiumoxide are all fine on musl. Attach the tarballs to the GitHub Release as
  well, since Linux aarch64 has no binary today. Then the Dockerfile only does
  `COPY --from=<binary> ...` per `TARGETARCH`, and the image build takes seconds.
- **Two tags, because Chromium dominates the size.** Alpine's `chromium` package is a few
  hundred MB, while the binary is about 11 MiB.
  - `:X.Y.Z-slim` / `:slim`: `alpine` + `ca-certificates` + `git` + the binary. reqwest uses the
    platform verifier, so it needs the CA store.
  - `:X.Y.Z` / `:latest`: the slim image plus `chromium` and `nss`, with `CHROME=/usr/bin/chromium-browser`
    and `GRANTCENTRAL_NO_SANDBOX=true`.
- Run as a non-root user and keep `ENTRYPOINT ["grantcentral"]`. Keep the `/work` volume
  convention from the current Dockerfile.
- Publish from the `release` job with `docker/build-push-action` (`platforms: linux/amd64,linux/arm64`,
  `permissions: packages: write`, `GITHUB_TOKEN`). Pushing an image is not a git ref, so this
  is compatible with the Forgejo mirror rule. build-push-action adds provenance and an SBOM
  by default.
- If musl's allocator turns out to be slow, add mimalloc, but measure first, because the
  runs are I/O-bound.
- Known limits, to document instead of fixing:
  - `login = system` has no browser inside a container.
  - `serve` binds to the container's `127.0.0.1`, which `-p` can't reach. Making it work
    would need a bind-address flag, which goes against the web UI's loopback-only rule.
    That needs a decision first, so the image targets `run` only.

## CI tasks: GitHub Actions and Azure Pipelines

Package a single `grantcentral run ...` invocation with inputs (`args` or `flows`, `env`,
`login`, `junit`, `json`, `version`) and upload the reports.

**Binary or Docker image? Default to the prebuilt binary, and keep the image as the fallback.**

| | Prebuilt binary | Docker image |
|---|---|---|
| Runner OS | Linux, macOS, Windows | Linux only. GitHub `runs.using: docker` actions and Azure container jobs can't run on macOS/Windows agents |
| Startup | ~11 MiB download, cacheable in the tool cache | pull of 15 MB (slim) to a few hundred MB (Chromium) per job, unless the agent caches it |
| Chromium | GitHub- and Microsoft-hosted Ubuntu images already ship Chrome; point `CHROME` at it | bundled |
| Secrets/env | inherits the job environment | every `GC_*` variable has to be passed through with `-e` |
| Self-hosted agents without Chrome | the user installs Chrome | works out of the box |

- **GitHub Action:** a composite `action.yml` at the repo root, so it can be used as
  `uses: <owner>/grantcentral@v0`. It downloads the release tarball for `runner.os`/`runner.arch`,
  verifies a `SHA256SUMS` file (add it to the release job), caches the binary, and sets
  `CHROME` from `browser-actions/setup-chrome` when the runner has no Chrome. It needs a
  moving `v0` major tag. That tag has to be pushed to Forgejo, because CI here never pushes
  tags. Publish it on the Marketplace once it is stable.
- **Azure Pipelines:** start with a YAML step template (`ci/azure/grantcentral.yml`) consumed
  through `resources.repositories`. It does the same download/verify/run and publishes the
  JUnit report with `PublishTestResults@2`. A real Marketplace task (a VSIX built with `tfx`,
  a publisher account, a Node task runner) takes noticeably more upkeep, so build it only if
  users ask.
- Both get a `container: true` (or `image:`) input that runs the GHCR image instead, for
  self-hosted Linux agents without Chrome.
- Test the GitHub Action against the e2e suite in `ci.yml`. The Azure template has no CI here,
  so document it with a sample pipeline.

## CIMD (Client ID Metadata Documents)

[draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)
(July 2026, WG draft). The `client_id` is an HTTPS URL, and the AS fetches the client's metadata
from it instead of using registration. MCP authorization is built on it, so many new
authorization servers will implement it.

**The happy path probably works today without code changes.** `client_id` is just a string, and
`auth_method` falls back to `none` without a secret, or to `private_key_jwt` with
`signing_key` + a `jwks_uri` in the document. Confirm that with an e2e flow before
building anything.

**Hosting is the user's job, not ours.** The AS must refuse to fetch from special-use IPs
(§8.6), so a real AS can't fetch a document that GrantCentral serves on loopback. The user
publishes static JSON (GitHub Pages, S3, ...). That also keeps the "client only" scope
intact. The only thing worth building for hosting is `grantcentral cimd generate <base-url> <dir>`, which
writes the valid document plus the negative variants below from `[client]`. Build it if
writing them by hand turns out to be tedious.

What to test:

- `audit`: `client_id_metadata_document_supported` (Info, §6).
- **Negative tests that need no hosting.** Send them as PAR requests, so the rejection comes
  back as JSON instead of an error page that the login drivers can't assert on.
  - Malformed client_id URLs must be rejected (§3): `http://`, userinfo, no path, `.`/`..`
    segments (including `%2e`), and a fragment.
  - SSRF (§8.6): `https://127.0.0.1/c`, `https://[::1]/c`, `https://169.254.169.254/c`, and a
    hostname that resolves to a private address.
- **Negative tests that need hosted variants** (§4, §4.1, §5, §8.7):
  - the document's `client_id` ≠ the URL;
  - `client_secret`, `client_secret_*` auth methods, or private key material in `jwks`;
  - `redirect_uri` not listed in the document;
  - a non-200 status, and a 3xx that the AS must not follow. The 3xx needs a host that can
    redirect, e.g. Netlify `_redirects`;
  - a document over 5 KB.
- `private_key_jwt` with the document's `jwks_uri`: the AS must require the assertion (§8.2).
- Loopback `redirect_uri` without a port in the document: does the AS apply RFC 8252 §7.3
  port-agnostic matching? This determines whether our per-run free port works with CIMD at all.
- Out of scope: cache behavior (§5.2), because it isn't observable from the client without
  timing games.

e2e: oidc-provider 9.12 has `features.clientIdMetadataDocument`. It leaves SSRF policy to the
`allowFetch` hook and doesn't block loopback by itself. `server.mjs` can serve the test
documents from its existing HTTPS listener (test-only, so that's allowed), with the
provider trusting the generated CA through `NODE_EXTRA_CA_CERTS`. Then add a README spec row.

## Opt-in diagnostic logging (`tracing-subscriber`)

axum, hyper, reqwest and chromiumoxide already emit `tracing`/`log` events, and today nothing
shows them. Add `tracing-subscriber` (with `env-filter` and `tracing-log` for the `log`-based
crates) to the CLI only, to debug the tool itself. The main case is Chromium/CDP failures.

- **Opt-in:** install no subscriber unless `RUST_LOG` is set, so default output stays exactly
  as it is.
- Write to stderr, so `--json`/`--junit` output and stdout stay clean.
- **Unredacted:** these events bypass `RunReport::redacted()`. reqwest logs request URLs at
  debug level, and they can carry tokens (`auth = "bearer_query"`, `code` in callbacks).
  Document `RUST_LOG` as a local developer tool, not for CI logs. Print a one-line stderr
  warning when it is set.
- `Run::log` stays as it is. Step logs are product output (reports, UI events, redaction), not
  diagnostics.
- Core keeps no subscriber. If core needs its own diagnostic events later, add `tracing` macros
  there (it's already in the tree via axum).

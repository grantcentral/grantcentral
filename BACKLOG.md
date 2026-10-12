# Backlog

## Smaller release binary

The release profile (`lto`, `codegen-units = 1`, `opt-level = "z"`, `strip`) takes the
Linux x86_64 binary from 38 MiB to 12.4 MiB. What remains is mostly dependencies
(`cargo bloat --release --crates` on the old profile, so sizes are relative):

- **Two crypto stacks (~1.8 MiB).** reqwest 0.13's default TLS is rustls with aws-lc,
  while josekit (and `jose.rs`, `lib.rs`) use OpenSSL. Options:
  - reqwest `native-tls` instead of the default: one stack on Linux, but Windows/macOS
    switch to SChannel/Security.framework and `Identity::from_pem` (mTLS) is rustls-only,
    so mTLS loading needs rework.
  - reqwest `rustls-no-provider` + rustls with `ring`: ring is smaller than aws-lc, still
    two stacks.
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

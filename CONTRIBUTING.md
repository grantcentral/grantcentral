# Contributing

## Build

You need Rust 1.88+ (edition 2024), a C compiler and git. All cryptography,
TLS included, comes from [aws-lc-rs](https://github.com/aws/aws-lc-rs), which
builds AWS-LC from source and links it statically.

```sh
cargo build --release
```

### Cross-compiling

From Linux to Windows, with MinGW (`apt install mingw-w64`):

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

macOS builds need Apple's SDK, which can't be redistributed. Build on a Mac
(`aarch64-apple-darwin` and `x86_64-apple-darwin` both work from one machine),
or from Linux with [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)
and an SDK you extract yourself:

```sh
SDKROOT=/path/to/MacOSX.sdk cargo zigbuild --release --target aarch64-apple-darwin
```

## Releases

The repository lives on Forgejo and is push-mirrored to GitHub, so releases start
from a tag pushed to Forgejo:

```sh
release-plz update                    # bump the version and CHANGELOG.md from Conventional Commits
git commit -am "chore: release vX.Y.Z"
git tag -a vX.Y.Z -m vX.Y.Z && git push --follow-tags   # --follow-tags skips lightweight tags
```

When the tag reaches GitHub, the Release workflow builds Linux, Windows and macOS
binaries, publishes both crates to crates.io and creates a GitHub Release with the
binaries and the changelog section. Running the workflow by hand only builds the
binaries, as workflow artifacts. They're unsigned: on macOS, clear the quarantine
flag with `xattr -d com.apple.quarantine grantcentral`.

## Development

```sh
cargo test --workspace            # unit and mock-server integration tests
e2e/run.sh                        # 14 flows against a local oidc-provider (Node 22+, openssl)
CHROME=/path/to/chrome e2e/run.sh # also the headless-Chromium device flow
```

`e2e/run.sh` starts `e2e/server.mjs` and generates throwaway mTLS
certificates. Without a Chrome it skips flows tagged `chromium`. The keys and
secrets under `e2e/project/keys/` are test values for that local server only.

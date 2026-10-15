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

When the tag reaches GitHub, the Release workflow builds the binaries (Linux
x86_64 glibc, static musl for Linux x86_64 and aarch64, Windows, macOS), runs the
e2e suite against the musl binaries and the amd64 images, publishes both crates to
crates.io and creates a GitHub Release with the binaries and the changelog section.
It then pushes the `ghcr.io/grantcentral/grantcentral` images (`X.Y.Z`/`latest` with
Chromium, `X.Y.Z-slim`/`slim` without, both for amd64 and arm64) with provenance and
an SBOM. Running the workflow by hand builds and tests everything but publishes
nothing. The binaries are unsigned: on macOS, clear the quarantine flag with
`xattr -d com.apple.quarantine grantcentral`.

The first image push creates the GHCR package as private. Make it public once in
the package settings, and link it to the repository there if GHCR didn't.

## Development

```sh
cargo test --workspace            # unit and mock-server integration tests
e2e/run.sh                        # 14 flows against a local oidc-provider (Node 22+, openssl)
CHROME=/path/to/chrome e2e/run.sh # also the headless-Chromium device flow
GRANTCENTRAL_IMAGE=grantcentral:slim GRANTCENTRAL="$PWD/e2e/docker.sh" e2e/run.sh --skip-tag chromium  # through an image
```

`e2e/run.sh` starts `e2e/server.mjs` and generates throwaway mTLS
certificates. Without a Chrome it skips flows tagged `chromium`. The keys and
secrets under `e2e/project/keys/` are test values for that local server only.

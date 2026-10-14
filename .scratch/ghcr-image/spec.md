# Multi-arch container image on GHCR

Status: ready-for-agent

## Problem Statement

People who want to run GrantCentral in a pipeline or on a machine without a Rust toolchain have no published image. The `Dockerfile` in the repository has to be built by each user from source, which compiles the whole workspace with LTO inside Docker and takes many minutes. It produces a Debian image of several hundred MB that always includes Chromium, even for users who only run `login = "http"` or token-only flows. It also still installs `libssl3`, which nothing has needed since OpenSSL was dropped.

There is also no Linux aarch64 binary at all. Users on ARM servers, Graviton CI runners, or Docker on Apple Silicon (which runs `linux/arm64` images) can't use GrantCentral without building it themselves.

## Solution

Every release publishes a multi-arch image, `ghcr.io/<owner>/grantcentral`, for `linux/amd64` and `linux/arm64`, in two variants:

- `:X.Y.Z-slim` / `:slim`: Alpine, CA certificates, git and the `grantcentral` binary. Tens of MB.
- `:X.Y.Z` / `:latest`: the slim image plus Chromium, preconfigured for headless logins (`CHROME` and `GRANTCENTRAL_NO_SANDBOX` already set).

The binary inside is a static musl build. The same musl builds for x86_64 and aarch64 are attached to the GitHub Release as tarballs, so Linux aarch64 users get a downloadable binary too. The image build only copies a binary that was already built and tested, so it takes seconds instead of a full compile under emulation.

Users run it the same way as today:

```
docker run --rm -v "$PWD:/work" ghcr.io/<owner>/grantcentral run --login chromium --junit report.xml
```

The image targets `grantcentral run` (and the other headless subcommands). `serve` works too: a new `--bind` flag (or `GRANTCENTRAL_BIND`) moves the web UI off `127.0.0.1`, so `-p` can reach it, and `GRANTCENTRAL_PORT` fixes the port that `-p` publishes:

```
docker run --rm -v "$PWD:/work" -p 8080:8080 -e GRANTCENTRAL_BIND=0.0.0.0 -e GRANTCENTRAL_PORT=8080 ghcr.io/<owner>/grantcentral serve --no-open
```

## User Stories

1. As a CI author, I want to pull a published GrantCentral image, so that I don't have to install Rust or build from source in my pipeline.
2. As a CI author, I want a small image without Chromium, so that pipelines that only run `http` logins or token flows start quickly.
3. As a CI author, I want an image with Chromium already configured, so that `--login chromium` works in a container without extra setup.
4. As a CI author, I want the Chromium image to set `CHROME` and `GRANTCENTRAL_NO_SANDBOX`, so that I don't need to know about Chromium sandbox flags in containers.
5. As a developer on Apple Silicon, I want a native `linux/arm64` image, so that Docker doesn't run GrantCentral under slow amd64 emulation.
6. As an operator of ARM CI runners (e.g. Graviton), I want a `linux/arm64` image, so that I can run GrantCentral on those runners.
7. As a Linux aarch64 user who doesn't use Docker, I want a prebuilt aarch64 binary on the GitHub Release, so that I can install GrantCentral without a Rust toolchain.
8. As a Linux user on any distribution, I want a static binary, so that it runs regardless of my glibc version.
9. As a CI author, I want version-pinned tags (`X.Y.Z` and `X.Y.Z-slim`), so that my pipeline doesn't change behavior under me.
10. As a casual user, I want moving `latest` and `slim` tags, so that I can try the current release without looking up a version.
11. As a CI author, I want pre-releases not to move `latest` or `slim`, so that a release candidate never reaches pipelines that follow the moving tags.
12. As a CI author, I want the image to keep the `/work` volume convention, so that the existing usage example keeps working.
13. As a CI author, I want `grantcentral` as the entrypoint, so that `docker run <image> run ...` reads the same as the CLI.
14. As a security-conscious user, I want the container to run as a non-root user by default, so that a compromised flow or browser can't act as root inside the container.
15. As a CI author who mounts my project with `-v`, I want to run the image as my own UID (`--user`), so that reports, JUnit files and screenshots written to `/work` are owned by me and not by an image-internal user.
16. As a CI author running as an arbitrary UID, I want Chromium to start anyway, so that `--user` doesn't break headless logins.
17. As a CI author, I want the image to trust the public CA store, so that HTTPS calls to real authorization servers verify.
18. As a CI author, I want git in the image, so that flows and projects checked out with git behave as on a workstation.
19. As a CI author, I want `env` secrets to work in the container, so that I can pass client secrets with `-e GC_...`.
20. As a CI author, I want the README to tell me that `keyring` secrets and `login = "system"` don't work in a container, so that I don't waste time debugging them.
21. As a user who wants the web UI from the container, I want to set `serve`'s bind address and port with flags or the `GRANTCENTRAL_BIND` and `GRANTCENTRAL_PORT` environment variables, so that `-p` can reach it.
22. As a supply-chain-conscious user, I want provenance attestations and an SBOM attached to the image, so that I can verify where it came from and what it contains.
23. As a user browsing GHCR, I want the image linked to the source repository, with its license, description and version labels, so that I can find the code and the changelog.
24. As a maintainer, I want the image published from the existing tag-driven release workflow, so that releases stay a single `git push --follow-tags` to Forgejo.
25. As a maintainer, I want publishing the image to push no git refs, so that it is compatible with the Forgejo push-mirror rule.
26. As a maintainer, I want the release to stop before anything is published if the musl binaries or the image fail the e2e suite, so that a broken image never reaches GHCR or crates.io.
27. As a maintainer, I want `workflow_dispatch` runs to build and test the images without pushing them, so that I can check the release pipeline without making a release.
28. As a maintainer, I want aarch64 binaries built on a native ARM runner, so that a release build with LTO doesn't take an hour under QEMU.
29. As a maintainer, I want a single `Dockerfile` that serves both variants, so that the two images can't drift apart.
30. As a maintainer, I want the `Dockerfile` header to say how to build the image locally, so that I can reproduce a release image on my machine.
31. As a maintainer, I want the image build to take seconds, so that the release workflow stays fast.
32. As a maintainer, I want the musl binaries' size and allocator performance measured before adding mimalloc, so that we only add a dependency if the numbers justify it.

## Implementation Decisions

**Binaries**

- Add `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` to the release build matrix. The aarch64 leg runs on GitHub's native `ubuntu-24.04-arm` runner; the x86_64 leg runs on the existing Ubuntu runner. Both install the musl toolchain package that aws-lc-sys's `cc` build needs. No cross-compilation tool (cross, zig) and no QEMU.
- The musl builds use the existing release profile and default features (Chromium support included). aws-lc-sys, zbus and chromiumoxide are expected to build on musl. If one doesn't, the fix belongs in that leg's build environment, not in a second feature set.
- Keep the existing `x86_64-unknown-linux-gnu` artifact. The musl tarballs are added alongside it under the same naming scheme (`grantcentral-<tag>-<target>.tar.gz`) and attached to the GitHub Release.
- No mimalloc. Runs are I/O-bound. If a measurement shows musl's allocator is a real cost, add it then.

**Image**

- One `Dockerfile` with two named stages: `slim` (from Alpine) and `full` (from `slim`). The build context is a directory holding the prebuilt musl binaries, one per Docker architecture name (`amd64`, `arm64`). Each stage selects its binary through BuildKit's `TARGETARCH`. The Dockerfile no longer compiles Rust.
- Pin the Alpine base to a minor version (e.g. `alpine:3.x`), not `latest`, so that a rebuild of the same tag gets the same Chromium major version.
- `slim`: `ca-certificates` and `git` from apk, the binary on `PATH`, a non-root user with a fixed UID, `WORKDIR /work`, `ENTRYPOINT ["grantcentral"]`. Drop `libssl3`.
- `full`: adds Alpine's `chromium` package and anything it needs at runtime (`nss` per the backlog; confirm against the package's own dependencies rather than duplicating them). Sets `CHROME` to the browser binary the Alpine package installs (verify the path, `chromium-browser` vs `chromium`, against the pinned Alpine version) and `GRANTCENTRAL_NO_SANDBOX=true`.
- Both stages set a world-writable `HOME` (e.g. `/tmp`), so that Chromium and git still work when the container runs as an arbitrary UID via `--user`. GrantCentral already puts the Chromium profile under the temp directory.
- OCI labels (source, license, description, version, revision) come from the metadata step in the workflow, not from hard-coded `LABEL` lines.

**Web UI bind address**

- `serve` gets `--bind <IP>` with clap's `env = "GRANTCENTRAL_BIND"` and default `127.0.0.1`, the same pattern as `GRANTCENTRAL_PROJECT` and `GRANTCENTRAL_NO_SANDBOX`. It takes an IP address (`std::net::IpAddr`), not a host name. Without the flag, behavior is unchanged.
- The existing `--port` gets `env = "GRANTCENTRAL_PORT"`. Its default stays `0` (a free port).
- The token check stays on every API call, whatever the bind address.
- The Host check changes from "exactly `127.0.0.1:<port>` or `localhost:<port>`" to "the host part is `localhost` or an IP literal (bracketed IPv6 included), any port". DNS rebinding needs a host name the attacker controls, so this still blocks it, and it lets through remapped ports (`-p 9000:8080` sends `Host: localhost:9000`) and access by IP from another machine. Other host names are still refused.
- With a non-loopback bind, `serve` warns on stderr that the UI is reachable from the network and that the token travels over plain HTTP. The printed URL uses the bind address, or `127.0.0.1` when it is unspecified (`0.0.0.0`, `::`).
- The image does not preset `GRANTCENTRAL_BIND`. Users opt in with `-e`. A preset would expose the UI on every host interface under `--network host`, which the e2e wrapper and the CI tasks use.
- README "The web UI" and the AGENTS.md "Web UI security" bullet describe the flag and the new Host rule.

**Release workflow**

- New `image` job, needs `build`. Runs on every trigger, including `workflow_dispatch`. It downloads the musl artifacts, lays out the build context, builds the `slim` and `full` images for `linux/amd64` only, loads them into the local Docker daemon, and runs the e2e suite against each of them (see Testing Decisions). It pushes nothing.
- The existing `publish` job (crates.io) now needs both `build` and `image`, so a failing image stops the release before crates.io.
- The existing `release` job gains `packages: write` and, after creating the GitHub Release, builds both stages for `linux/amd64,linux/arm64` with `docker/build-push-action` and pushes them to GHCR with `GITHUB_TOKEN`. Rebuilding here costs seconds because the Dockerfile only copies binaries.
- Tags come from `docker/metadata-action`, which also lowercases the owner (GHCR requires lowercase names): `X.Y.Z` and `latest` for `full`, `X.Y.Z-slim` and `slim` for `slim`. A pre-release version (e.g. `vX.Y.Z-rc.1`) gets only its version tag and doesn't move `latest` or `slim`.
- Enable provenance and SBOM attestations explicitly. build-push-action adds minimal provenance by default but no SBOM, so the backlog's "SBOM by default" claim is wrong.
- Nothing in the workflow pushes a git ref. Pushing an image is not a ref, so the Forgejo push-mirror rule holds.
- No separate image job in `ci.yml`. The image is only built where the musl binaries exist, which is the release workflow.

**Documentation**

- README: replace the "The `Dockerfile` builds an image..." sentence with a short "Container image" section: the two tags and when to pick which, the `docker run` example with `-v "$PWD:/work"`, passing secrets with `-e`, and running as your own UID with `--user "$(id -u):$(id -g)"` so that written reports are yours.
- README known limits, documented instead of fixed: `login = "system"` has no browser in the container; `keyring` secrets have no Secret Service in the container (use `env` or `file`); `login = "manual"` needs `-it`. Also a `serve` example with `-e GRANTCENTRAL_BIND=0.0.0.0`, `-e GRANTCENTRAL_PORT` and `-p`, plus the plain-HTTP warning.
- README "Releases": mention that the release also publishes the GHCR images and the musl tarballs.
- `Dockerfile` header comment: how to build locally (build the musl binary, place it in the context layout, `docker build --target slim|full`).

## Testing Decisions

- Good tests here exercise the published artifact the way a user would: the real binary or the real image running real flows against an authorization server, judged by exit code and the JUnit report. Don't test the Dockerfile's internals (layer contents, file lists).
- **The e2e suite is the only seam.** `e2e/run.sh` already accepts a `GRANTCENTRAL` override for the binary under test, and the flows already cover discovery, every grant, mTLS, DPoP, PAR and the Chromium logins. Prior art: the `e2e` job in `ci.yml`, which runs the suite against a debug build with Chrome from `browser-actions/setup-chrome`.
  - **musl binaries:** each musl leg of the release build matrix runs the suite with `GRANTCENTRAL` pointing at its freshly built release binary, on its native runner. The aarch64 runner probably has no Chrome for `setup-chrome` (Chrome for Testing has no Linux arm64 build). In that case the suite's existing auto-skip of `chromium`-tagged flows applies, and the log says so.
  - **Images:** a thin wrapper script next to the e2e runner stands in for the binary. It runs the image with host networking (so the container reaches the local OP and the OP's redirects reach the container's loopback listener), bind-mounts the e2e directory at the same absolute path and runs as the caller's UID. The `image` job runs the suite through the wrapper once per variant. `slim` runs with `--skip-tag chromium`. `full` runs every flow, with Chromium inside the image, so that the image's `CHROME`, no-sandbox and arbitrary-UID `HOME` are all exercised. The suite's Chrome auto-detection looks at the host, so the wrapper invocation for `full` must tell it a browser exists, rather than letting it skip.
  - Upload the JUnit report, OP log and screenshots as artifacts on failure, as the `ci.yml` e2e job does.
- The `linux/arm64` image is not run in CI. It differs from the tested amd64 image only in the binary it copies (tested natively above) and the arch of the same apk packages. Running it would need Docker on the ARM runner as well. Add that only if an arm64-only image bug shows up.
- **Bind address:** unit tests for the Host check as a pure function over the header value: `localhost`, IPv4 and bracketed IPv6 literals pass with any port; other host names and a missing header fail. In the `image` job, one smoke step runs `slim` with `-e GRANTCENTRAL_BIND=0.0.0.0 -e GRANTCENTRAL_PORT=... -p` and `serve`, and checks that `/` answers 200 through the published port.
- `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` and the existing `ci.yml` e2e job are unaffected and must keep passing.

## Out of Scope

- TLS for `serve`. A non-loopback bind sends the token over plain HTTP; the warning and the README say so.
- An allow-list for host names other than `localhost` in the Host check.
- A browser for `login = "system"` in the container, and a Secret Service for `keyring` secrets.
- A slim *binary* without the `chromium` feature. The slim image only drops the browser, not the code.
- Images for other platforms (`linux/arm/v7`, Windows containers) and Docker Hub or other registries.
- Image signing with cosign/sigstore beyond the provenance attestation build-push-action produces.
- Building the image in `ci.yml` on every push.
- Replacing the glibc Linux tarball with the musl one.
- The CI tasks (GitHub Action, Azure Pipelines template). They are a separate backlog entry and will consume this image as a fallback.
- mimalloc, until a measurement justifies it.

## Further Notes

- The first push creates the GHCR package as private. A maintainer has to make it public once in the package settings, and should link it to the repository if the source label doesn't do that automatically. This is a human step and belongs in the release checklist, not the workflow.
- The release job's `GITHUB_TOKEN` can only push to a package the repository owns or has been granted write access to. If the package was ever created by hand under another owner, fix the package's "Manage Actions access" setting.
- Record the image sizes of both variants (both arches) in the PR, next to today's Debian image, so the backlog's size claims can be checked.
- The CI-tasks backlog entry plans a `SHA256SUMS` file on the release. If it lands first, include the musl tarballs in it. If this lands first, the CI-tasks work adds them.

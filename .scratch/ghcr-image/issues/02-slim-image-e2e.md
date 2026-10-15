# 02: Slim image, built and e2e-tested in the release workflow

**What to build:** The `Dockerfile` stops compiling Rust. It becomes an Alpine image that copies the musl binary from ticket 01 for the platform being built, and contains only CA certificates, git and `grantcentral`. The Release workflow gets a new `image` job that builds this `slim` image for `linux/amd64`, loads it locally and runs the e2e suite through it. Nothing is pushed to a registry yet. The crates.io publish now waits for this job, so a broken image stops the release before anything is published. See the spec (`../spec.md`), "Image", "Release workflow" and "Testing Decisions".

**Blocked by:** 01 (Static musl binaries on the release, e2e-tested)

**Status:** ready-for-agent

- [ ] The `Dockerfile` has a `slim` stage from an Alpine base pinned to a minor version (`alpine:3.x`, not `latest`). The build context is a directory holding one prebuilt binary per Docker architecture name (`amd64`, `arm64`), and the stage picks its binary through BuildKit's `TARGETARCH`.
- [ ] `slim` installs `ca-certificates` and `git` from apk, and not `libssl3`. It puts the binary on `PATH`, creates a non-root user with a fixed UID and runs as that user. It sets a world-writable `HOME` (e.g. `/tmp`), `WORKDIR /work` and `ENTRYPOINT ["grantcentral"]`.
- [ ] Running as an arbitrary UID with `--user "$(id -u):$(id -g)"` and a bind-mounted `/work` works, and files the run writes there belong to the caller.
- [ ] A small wrapper script next to `e2e/run.sh` runs a given image in place of the binary. It uses host networking, bind-mounts the e2e directory at the same absolute path, uses the current directory as the working directory, runs as the caller's UID and passes its arguments through. `e2e/run.sh` uses it through the existing `GRANTCENTRAL` override, with no new test harness.
- [ ] A new `image` job, which needs `build`, runs on every trigger including `workflow_dispatch`. It downloads the musl artifacts, lays out the build context, builds `slim` for `linux/amd64` with `load: true` and runs the suite through the wrapper with `--skip-tag chromium`. It pushes nothing.
- [ ] On failure, the `image` job uploads the JUnit report, the OP log and screenshots.
- [ ] The `publish` job (crates.io) needs both `build` and `image`.
- [ ] The `Dockerfile` header comment is updated so it no longer claims a from-source build. The full local-build recipe comes in ticket 04.
- [ ] The README sentence about the `Dockerfile` (which says it includes Chromium) is no longer false. A minimal fix is fine here, since ticket 04 writes the full "Container image" section.
- [ ] Nothing in the workflow pushes a git ref.
- [ ] Committed as `ci:` or `feat:`. No version bump and no `CHANGELOG.md` edit.

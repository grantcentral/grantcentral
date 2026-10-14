# 01: Static musl binaries on the release, e2e-tested

**What to build:** Every release (and every `workflow_dispatch` run of the Release workflow) builds static `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` binaries. Each one is built on its native runner: the existing Ubuntu runner for x86_64, and GitHub's `ubuntu-24.04-arm` for aarch64. No QEMU, no cross or zig. Each binary must pass the e2e suite on the runner that built it before the release can continue. On a tag push, both tarballs are attached to the GitHub Release, so Linux aarch64 users get a downloadable binary for the first time. These binaries are what tickets 02–04 copy into the image. See the spec (`../spec.md`).

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The release build matrix has both musl targets, using the existing release profile and default features (Chromium support included). Each leg installs the musl toolchain that aws-lc-sys's `cc` build needs. If a crate doesn't build on musl, fix that leg's build environment. Don't add a second feature set.
- [ ] The tarballs follow the existing naming scheme (`grantcentral-<tag>-<target>.tar.gz`) and are uploaded as workflow artifacts, as the other targets are. The existing `x86_64-unknown-linux-gnu` artifact stays.
- [ ] Each musl leg runs `e2e/run.sh` with `GRANTCENTRAL` pointing at its fresh release binary (Node 22 set up, as in the `ci.yml` e2e job). x86_64 gets Chrome from `browser-actions/setup-chrome` and runs every flow. On aarch64, if `setup-chrome` has no build, the suite's existing auto-skip of `chromium`-tagged flows applies and the log says so.
- [ ] The JUnit report, the OP log and screenshots are uploaded as artifacts when an e2e run fails, as `ci.yml` does.
- [ ] The resulting binary is static: `file` or `ldd` on each one shows no dynamic loader. The x86_64 binary runs on a glibc-free system (e.g. `alpine`).
- [ ] The existing `release` job attaches both musl tarballs to the GitHub Release with no other changes, since it already uploads every downloaded artifact.
- [ ] README "Releases" lists Linux x86_64 and aarch64 musl binaries among the release artifacts.
- [ ] The PR records both musl binary sizes next to the glibc one. No mimalloc.
- [ ] Nothing in the workflow pushes a git ref.
- [ ] Committed as `ci:` (or `feat:` if the README change is the user-facing part). No version bump and no `CHANGELOG.md` edit.
